package rbac

import (
	"sort"
	"strings"
)

// This file builds the permission graph: it resolves every binding to its role's
// rules and produces, per subject, the flattened set of things that subject can
// do. From that we answer both directions — "what can this subject do?" and the
// far more useful audit question, "who can do X on Y?". Resolution mirrors
// Kubernetes semantics closely enough for risk analysis: a namespaced RoleBinding
// to a ClusterRole grants only within that namespace; a ClusterRoleBinding grants
// everywhere.

// --- Permission ----------------------------------------------------------

// Permission is one concrete capability a subject holds: a verb on a resource in
// an apiGroup, scoped to a namespace ("" meaning cluster-wide / all namespaces).
// It is the atom of both the effective-permission set and observed-usage data.
type Permission struct {
	Verb      string
	APIGroup  string
	Resource  string
	Namespace string // "" = cluster-wide
}

// String renders a permission compactly for output and least-privilege diffs,
// e.g. "get secrets.core in kube-system" or "* *.* cluster-wide".
func (p Permission) String() string {
	grp := p.APIGroup
	if grp == "" {
		grp = "core"
	}
	scope := "cluster-wide"
	if p.Namespace != "" {
		scope = "in " + p.Namespace
	}
	return p.Verb + " " + p.Resource + "." + grp + " " + scope
}

// --- Grant: a resolved binding edge --------------------------------------

// Grant is a resolved binding: which subject got which role's rules, and in what
// scope. It is the intermediate the whole analysis is built on, and it records
// enough provenance (binding and role names) to explain any finding.
type Grant struct {
	Subject     Subject
	Role        *Role
	Binding     *Binding
	Namespace   string // effective scope of the grant ("" = cluster-wide)
	ClusterWide bool
}

// --- Graph ---------------------------------------------------------------

// Graph is the resolved RBAC universe: every grant, indexed for the reverse
// queries that make an access review tractable.
type Graph struct {
	Grants []Grant
	// dangling records bindings whose roleRef resolves to no known role; these
	// are both a hygiene problem and a place where intent silently does nothing.
	dangling []*Binding
	cluster  *Cluster
}

// buildGraph resolves every binding against the cluster's roles. Bindings whose
// role is missing are recorded as dangling rather than dropped, because a
// dangling binding is itself a finding.
func buildGraph(c *Cluster) *Graph {
	g := &Graph{cluster: c}
	for _, b := range c.Bindings {
		role := resolveRole(c, b)
		if role == nil {
			g.dangling = append(g.dangling, b)
			continue
		}
		for _, s := range b.Subjects {
			g.Grants = append(g.Grants, Grant{
				Subject:     s,
				Role:        role,
				Binding:     b,
				Namespace:   grantScope(b),
				ClusterWide: b.ClusterScoped,
			})
		}
	}
	// Deterministic order so downstream walks and golden output are stable.
	sort.SliceStable(g.Grants, func(i, j int) bool {
		if g.Grants[i].Subject.key() != g.Grants[j].Subject.key() {
			return g.Grants[i].Subject.key() < g.Grants[j].Subject.key()
		}
		return g.Grants[i].Role.Name < g.Grants[j].Role.Name
	})
	return g
}

// resolveRole finds the Role/ClusterRole a binding references. A RoleBinding may
// reference either a namespaced Role (looked up in the binding's namespace) or a
// ClusterRole (looked up cluster-wide); a ClusterRoleBinding references only a
// ClusterRole.
func resolveRole(c *Cluster, b *Binding) *Role {
	switch b.RoleRef.Kind {
	case "ClusterRole":
		return c.Roles[roleKey(true, "", b.RoleRef.Name)]
	case "Role":
		return c.Roles[roleKey(false, b.Namespace, b.RoleRef.Name)]
	default:
		// Some exports omit roleRef.kind; try both, preferring the namespaced
		// role, then the cluster role.
		if r := c.Roles[roleKey(false, b.Namespace, b.RoleRef.Name)]; r != nil {
			return r
		}
		return c.Roles[roleKey(true, "", b.RoleRef.Name)]
	}
}

// grantScope returns the effective namespace of a binding's grant. A
// ClusterRoleBinding is cluster-wide (""); a RoleBinding is scoped to its own
// namespace even when it points at a ClusterRole.
func grantScope(b *Binding) string {
	if b.ClusterScoped {
		return ""
	}
	return b.Namespace
}

// --- Effective permissions ----------------------------------------------

// SubjectPermissions returns the flattened permission set for one subject key,
// expanding each granted role's rules into concrete Permission atoms. Wildcards
// are preserved as "*" rather than expanded against a resource catalog — we do
// not ship one, and for risk purposes "*" is more honest than a frozen list.
func (g *Graph) SubjectPermissions(subjectKey string) []Permission {
	seen := map[Permission]struct{}{}
	var out []Permission
	for _, gr := range g.Grants {
		if gr.Subject.key() != subjectKey {
			continue
		}
		for _, rule := range gr.Role.Rules {
			for _, perm := range expandRule(rule, gr.Namespace) {
				if _, ok := seen[perm]; ok {
					continue
				}
				seen[perm] = struct{}{}
				out = append(out, perm)
			}
		}
	}
	sortPermissions(out)
	return out
}

// expandRule turns one PolicyRule into its Permission atoms (verb × apiGroup ×
// resource) in the given scope. NonResourceURL rules are surfaced as a synthetic
// resource so they are not silently lost.
func expandRule(r PolicyRule, namespace string) []Permission {
	var out []Permission
	groups := defaulted(r.APIGroups)
	resources := defaulted(r.Resources)
	for _, v := range r.Verbs {
		for _, grp := range groups {
			for _, res := range resources {
				out = append(out, Permission{Verb: v, APIGroup: grp, Resource: res, Namespace: namespace})
			}
		}
		for _, u := range r.NonResourceURLs {
			out = append(out, Permission{Verb: v, APIGroup: "nonResourceURL", Resource: u, Namespace: namespace})
		}
	}
	return out
}

// defaulted returns a single empty element when a rule field is absent, so the
// cross-product in expandRule always runs at least once (matching how an empty
// apiGroups list still yields core-group permissions).
func defaulted(xs []string) []string {
	if len(xs) == 0 {
		return []string{""}
	}
	return xs
}

// --- Reverse queries: "who can X on Y" -----------------------------------

// WhoCan returns every subject that can perform verb on resource (in apiGroup),
// optionally restricted to a namespace. This is the access-review workhorse:
// wildcards in a subject's grant match any query, which is exactly the danger
// wildcards represent. An empty namespace query matches grants in any scope.
func (g *Graph) WhoCan(verb, apiGroup, resource, namespace string) []Subject {
	seen := map[string]Subject{}
	for _, gr := range g.Grants {
		if namespace != "" && gr.Namespace != "" && gr.Namespace != namespace {
			continue // grant is scoped to a different namespace
		}
		for _, rule := range gr.Role.Rules {
			if ruleMatches(rule, verb, apiGroup, resource) {
				seen[gr.Subject.key()] = gr.Subject
				break
			}
		}
	}
	out := make([]Subject, 0, len(seen))
	for _, s := range seen {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// ruleMatches reports whether a rule permits verb on resource in apiGroup,
// honoring "*" wildcards in each dimension the way the API server does.
func ruleMatches(r PolicyRule, verb, apiGroup, resource string) bool {
	return contains(r.Verbs, verb) && contains(defaulted(r.APIGroups), apiGroup) && contains(defaulted(r.Resources), resource)
}

// contains reports membership, treating "*" as a match-all wildcard.
func contains(set []string, want string) bool {
	for _, s := range set {
		if s == "*" || s == want {
			return true
		}
	}
	return false
}

// --- Small ordering helpers ----------------------------------------------

func sortPermissions(ps []Permission) {
	sort.Slice(ps, func(i, j int) bool { return ps[i].String() < ps[j].String() })
}

// subjectKeys returns every distinct subject in the graph, sorted — the stable
// iteration order the analysis and NHI passes rely on.
func (g *Graph) subjectKeys() []string {
	seen := map[string]struct{}{}
	for _, gr := range g.Grants {
		seen[gr.Subject.key()] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// subjectByKey returns the Subject value for a key (first grant seen). Used to
// recover Kind/Namespace when reporting.
func (g *Graph) subjectByKey(key string) Subject {
	for _, gr := range g.Grants {
		if gr.Subject.key() == key {
			return gr.Subject
		}
	}
	return Subject{Name: strings.TrimPrefix(key, "User/")}
}
