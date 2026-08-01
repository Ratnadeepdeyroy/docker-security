package rbac

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// This file answers the question that matters most in an incident: "from a
// foothold in this pod, can the attacker reach cluster-admin or root on a node?"
// We model escalation as reachability over a small graph of principals. Each
// subject gets outgoing edges for the privilege-escalation primitives it holds
// (bind, escalate, impersonate, secret/token theft, CSR forging, workload
// creation, node/kubelet access). A breadth-first search from each pod's
// identity to the two terminal targets — cluster-admin and node-root — yields a
// concrete, explainable path. This is deliberately conservative: we only add an
// edge for a primitive that is genuinely sufficient on its own, so a reported
// path is a real path, not a maybe.

// --- Terminal targets ----------------------------------------------------

const (
	targetClusterAdmin = "target:cluster-admin"
	targetNodeRoot     = "target:node-root"
)

// escEdge is a directed escalation step with the human reason it exists. Reasons
// become the narration of the reported path.
type escEdge struct {
	to     string
	reason string
}

// --- Escalation graph ----------------------------------------------------

// buildEscalationEdges computes, for every subject, the escalation steps it can
// take. It returns an adjacency map keyed by principal. Targets have no outgoing
// edges (they are sinks). We do NOT link node-root → cluster-admin automatically:
// harvesting a privileged token off a node is real but situational, and we prefer
// to report exactly the terminal actually reached rather than over-claim.
func buildEscalationEdges(c *Cluster, g *Graph) map[string][]escEdge {
	adj := map[string][]escEdge{}
	add := func(from, to, reason string) { adj[from] = append(adj[from], escEdge{to: to, reason: reason}) }

	// Which subjects can steal any identity (secret read or token mint)? They can
	// become any ServiceAccount, so they inherit every SA's reachability.
	saKeys := serviceAccountSubjectKeys(g)

	for _, sk := range g.subjectKeys() {
		permList := g.SubjectPermissions(sk)
		perms := indexPerms(permList)

		if boundToClusterAdmin(g, sk) {
			add(sk, targetClusterAdmin, "bound directly to cluster-admin/system:masters")
		}
		if perms.has("escalate", "roles") || perms.has("escalate", "clusterroles") || perms.has("escalate", "*") {
			add(sk, targetClusterAdmin, "holds 'escalate' — can self-grant any permission")
		}
		if perms.has("bind", "clusterroles") || perms.has("bind", "*") {
			add(sk, targetClusterAdmin, "holds 'bind' — can bind cluster-admin to itself")
		}
		if perms.hasVerb("impersonate") {
			add(sk, targetClusterAdmin, "holds 'impersonate' — can impersonate system:masters")
		}
		if (perms.has("create", "certificatesigningrequests") || perms.has("*", "certificatesigningrequests")) &&
			(perms.has("update", "certificatesigningrequests/approval") || perms.has("*", "signers") || perms.has("*", "certificatesigningrequests/approval")) {
			add(sk, targetClusterAdmin, "can create and approve CSRs — forge a system:masters client cert")
		}
		if perms.hasAnyResource("create", "pods", "deployments", "daemonsets", "statefulsets", "jobs") ||
			perms.has("*", "pods") {
			add(sk, targetNodeRoot, "can create workloads — schedule a privileged pod to gain host root")
		}
		if perms.has("get", "nodes/proxy") || perms.has("*", "nodes/proxy") || perms.hasAnyResource("get", "nodes") {
			add(sk, targetNodeRoot, "has node/kubelet access — reach every pod on a node")
		}
		// Identity theft: reading Secrets (which hold SA tokens) or minting
		// tokens lets a subject assume other ServiceAccounts. Secrets are
		// namespaced, so we scope this carefully — a cluster-wide grant assumes
		// ANY SA, whereas a namespaced grant assumes only SAs in that namespace.
		// This keeps reported escalation paths defensible rather than sprayed.
		clusterSteal, stealNS := identityTheftScope(permList)
		if clusterSteal || len(stealNS) > 0 {
			for _, other := range saKeys {
				if other == sk {
					continue
				}
				_, inNS := stealNS[subjectNamespace(other)]
				if clusterSteal || inNS {
					add(sk, other, "can read Secrets / mint tokens — assume identity "+strings.TrimPrefix(other, "ServiceAccount/"))
				}
			}
		}
	}
	// Stable edge order keeps BFS (and paths) deterministic.
	for k := range adj {
		sort.Slice(adj[k], func(i, j int) bool {
			if adj[k][i].to != adj[k][j].to {
				return adj[k][i].to < adj[k][j].to
			}
			return adj[k][i].reason < adj[k][j].reason
		})
	}
	return adj
}

// checkEscalationPaths finds, for each pod (or each ServiceAccount when there are
// no pods), the shortest escalation path to a terminal target and reports it.
func checkEscalationPaths(c *Cluster, g *Graph) []Risk {
	adj := buildEscalationEdges(c, g)
	var rs []Risk

	// Start from every pod (concrete blast radius from a real foothold) AND from
	// any ServiceAccount not already backing a pod (a powerful but currently
	// unscheduled identity is still a latent escalation source).
	starts := podStarts(c)
	covered := map[string]bool{}
	for _, s := range starts {
		covered[s.subjectKey] = true
	}
	for _, s := range saStarts(g) {
		if !covered[s.subjectKey] {
			starts = append(starts, s)
			covered[s.subjectKey] = true
		}
	}
	sort.Slice(starts, func(i, j int) bool { return starts[i].origin < starts[j].origin })

	for _, st := range starts {
		path, target := bfsToTarget(adj, st.subjectKey)
		if target == "" {
			continue
		}
		narration := append([]string{st.origin}, path...)
		rs = append(rs, Risk{
			RuleID:      "DS-RAT-RBAC-014",
			Severity:    engine.SeverityCritical,
			Title:       fmt.Sprintf("Privilege-escalation path from %s to %s", st.origin, prettyTarget(target)),
			Description: strings.Join(narration, "  →  "),
			Subject:     st.subjectKey,
			Resource:    prettyTarget(target),
			Remediation: "Break the chain: remove the escalation primitive named in the first hop, or block privileged pod creation at admission (Phase 4).",
			References:  []string{refMitrePrivEsc, refMitreEscape, refK8sHarden},
			Path:        narration,
			Meta:        map[string]string{"target": prettyTarget(target), "hops": fmt.Sprintf("%d", len(path))},
		})
	}
	return dedupe(rs)
}

// bfsToTarget runs a breadth-first search from start to the nearest terminal
// target, returning the path (as reason-annotated hops) and which target was
// reached. Bounded by the number of principals, so it always terminates.
func bfsToTarget(adj map[string][]escEdge, start string) ([]string, string) {
	type node struct {
		key  string
		path []string
	}
	visited := map[string]bool{start: true}
	queue := []node{{key: start}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, e := range adj[cur.key] {
			if e.to == targetClusterAdmin || e.to == targetNodeRoot {
				return append(cur.path, e.reason+" ⇒ "+prettyTarget(e.to)), e.to
			}
			if visited[e.to] {
				continue
			}
			visited[e.to] = true
			hop := fmt.Sprintf("%s (%s)", strings.TrimPrefix(e.to, "ServiceAccount/"), e.reason)
			queue = append(queue, node{key: e.to, path: append(append([]string{}, cur.path...), hop)})
		}
	}
	return nil, ""
}

// --- Least-privilege generation ------------------------------------------

// GenerateLeastPrivilege builds the minimal Role that would cover exactly the
// permissions a subject was observed using (from audit data). It is the
// constructive counterpart to the risk report: instead of only saying "this is
// over-broad", it hands back the tight role to replace it with. Permissions are
// grouped by apiGroup and rendered deterministically.
func GenerateLeastPrivilege(subjectKey string, observed []Permission) *Role {
	// group[apiGroup] -> set of verbs and resources actually used together.
	type bucket struct {
		verbs     map[string]struct{}
		resources map[string]struct{}
	}
	groups := map[string]*bucket{}
	for _, p := range observed {
		b := groups[p.APIGroup]
		if b == nil {
			b = &bucket{verbs: map[string]struct{}{}, resources: map[string]struct{}{}}
			groups[p.APIGroup] = b
		}
		b.verbs[p.Verb] = struct{}{}
		b.resources[p.Resource] = struct{}{}
	}
	role := &Role{Name: leastPrivName(subjectKey)}
	for _, grp := range sortedKeys(groups) {
		b := groups[grp]
		role.Rules = append(role.Rules, PolicyRule{
			APIGroups: []string{grp},
			Resources: setToSorted(b.resources),
			Verbs:     setToSorted(b.verbs),
		})
	}
	return role
}

// --- Helpers -------------------------------------------------------------

// permIndex is a fast membership set over a subject's permissions, supporting
// wildcard-aware lookups the escalation edges need.
type permIndex struct {
	byVR  map[string]struct{} // "verb|resource"
	verbs map[string]struct{}
}

func indexPerms(ps []Permission) permIndex {
	idx := permIndex{byVR: map[string]struct{}{}, verbs: map[string]struct{}{}}
	for _, p := range ps {
		idx.byVR[p.Verb+"|"+p.Resource] = struct{}{}
		idx.verbs[p.Verb] = struct{}{}
	}
	return idx
}

func (i permIndex) has(verb, resource string) bool {
	_, ok := i.byVR[verb+"|"+resource]
	return ok
}
func (i permIndex) hasVerb(verb string) bool { _, ok := i.verbs[verb]; return ok }
func (i permIndex) hasAnyResource(verb string, resources ...string) bool {
	for _, r := range resources {
		if i.has(verb, r) {
			return true
		}
	}
	return false
}

// identityTheftScope inspects a subject's permissions for the ability to steal
// other identities — reading Secrets or minting tokens. It returns whether the
// grant is cluster-wide (can assume any SA) and, otherwise, the set of
// namespaces in which it can (where the relevant Secrets/tokens live).
func identityTheftScope(perms []Permission) (clusterWide bool, namespaces map[string]struct{}) {
	namespaces = map[string]struct{}{}
	for _, p := range perms {
		theft := false
		switch {
		case (p.Verb == "get" || p.Verb == "list" || p.Verb == "watch" || p.Verb == "*") && (p.Resource == "secrets" || p.Resource == "*"):
			theft = true
		case p.Verb == "create" && (p.Resource == "serviceaccounts/token" || p.Resource == "tokenrequests"):
			theft = true
		case p.Verb == "*" && (p.Resource == "serviceaccounts/token" || p.Resource == "tokenrequests"):
			theft = true
		}
		if !theft {
			continue
		}
		if p.Namespace == "" {
			clusterWide = true
		} else {
			namespaces[p.Namespace] = struct{}{}
		}
	}
	return clusterWide, namespaces
}

// subjectNamespace extracts the namespace from a "ServiceAccount/<ns>/<name>"
// key; returns "" for non-namespaced subject keys.
func subjectNamespace(subjectKey string) string {
	parts := strings.Split(subjectKey, "/")
	if len(parts) == 3 && parts[0] == "ServiceAccount" {
		return parts[1]
	}
	return ""
}

func boundToClusterAdmin(g *Graph, subjectKey string) bool {
	for _, gr := range g.Grants {
		if gr.Subject.key() != subjectKey {
			continue
		}
		if gr.Role.ClusterScoped && gr.Role.Name == "cluster-admin" {
			return true
		}
		if gr.Subject.Kind == "Group" && gr.Subject.Name == "system:masters" {
			return true
		}
	}
	return false
}

func serviceAccountSubjectKeys(g *Graph) []string {
	var out []string
	seen := map[string]bool{}
	for _, gr := range g.Grants {
		if gr.Subject.Kind == "ServiceAccount" && !seen[gr.Subject.key()] {
			seen[gr.Subject.key()] = true
			out = append(out, gr.Subject.key())
		}
	}
	sort.Strings(out)
	return out
}

type startPoint struct {
	origin     string // human label of where the chain starts
	subjectKey string
}

// podStarts returns one escalation start per pod, mapped to the SA identity the
// pod actually runs as.
func podStarts(c *Cluster) []startPoint {
	var out []startPoint
	for _, p := range c.Pods {
		sk := Subject{Kind: "ServiceAccount", Name: p.effectiveSA(), Namespace: p.Namespace}.key()
		out = append(out, startPoint{
			origin:     fmt.Sprintf("Pod %s/%s (as %s)", p.Namespace, p.Name, sk),
			subjectKey: sk,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].origin < out[j].origin })
	return out
}

// saStarts returns one start per ServiceAccount subject, used when no pods were
// supplied so powerful dormant SAs are still surfaced.
func saStarts(g *Graph) []startPoint {
	var out []startPoint
	for _, sk := range serviceAccountSubjectKeys(g) {
		out = append(out, startPoint{origin: strings.TrimPrefix(sk, "ServiceAccount/"), subjectKey: sk})
	}
	return out
}

func prettyTarget(t string) string {
	switch t {
	case targetClusterAdmin:
		return "cluster-admin"
	case targetNodeRoot:
		return "node-root"
	default:
		return strings.TrimPrefix(t, "ServiceAccount/")
	}
}

func leastPrivName(subjectKey string) string {
	safe := strings.NewReplacer("/", "-", ":", "-", "*", "wildcard").Replace(subjectKey)
	return "least-privilege-" + strings.ToLower(safe)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func setToSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
