package rbac

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// This file holds the individual RBAC risk checks. Each check is a small,
// independently testable function that reads the Cluster/Graph and appends Risk
// values. They map to well-known privilege-escalation primitives documented in
// the Kubernetes RBAC hardening guidance and MITRE ATT&CK for Containers — the
// verbs and resources that, alone, turn "access to a namespace" into "access to
// the cluster". Keeping each primitive in its own function makes the parity
// checklist auditable: one function, one line on the checklist.

// --- Risky-verb and resource vocabularies --------------------------------

// riskyVerbs are verbs that grant power over RBAC itself or over other
// identities — the classic self-escalation and lateral-movement levers.
var riskyVerbs = map[string]struct {
	rule string
	sev  engine.Severity
	why  string
}{
	"escalate":    {"DS-RAT-RBAC-003", engine.SeverityHigh, "can grant permissions it does not itself hold (escalate)"},
	"bind":        {"DS-RAT-RBAC-004", engine.SeverityHigh, "can bind any role to any subject (bind), including cluster-admin"},
	"impersonate": {"DS-RAT-RBAC-005", engine.SeverityHigh, "can act as other users/groups/service accounts (impersonate)"},
}

// checkAll runs every RBAC check over the cluster and returns the deterministic,
// de-duplicated risk set. It is the single entry the module and CLI both call.
func checkAll(c *Cluster, g *Graph, opts Options) []Risk {
	var rs []Risk
	rs = append(rs, checkWildcards(c)...)
	rs = append(rs, checkRiskyVerbs(g)...)
	rs = append(rs, checkClusterAdmin(g)...)
	rs = append(rs, checkSecretReaders(g)...)
	rs = append(rs, checkExec(g)...)
	rs = append(rs, checkProxyAndNodes(g)...)
	rs = append(rs, checkTokenMint(g)...)
	rs = append(rs, checkCSRSigning(g)...)
	rs = append(rs, checkWorkloadCreation(g)...)
	rs = append(rs, checkBroadSubjects(g)...)
	rs = append(rs, checkDangling(g)...)
	rs = append(rs, checkDefaultSA(c)...)
	rs = append(rs, checkCloudIAM(c)...)
	rs = append(rs, checkDockerHosts(c)...)
	rs = append(rs, checkEscalationPaths(c, g)...)
	if opts.EnableNHI {
		rs = append(rs, checkNHI(c, g, opts)...)
	}
	sortRisks(rs)
	return rs
}

// --- Role-level checks ---------------------------------------------------

// checkWildcards flags roles granting "*" on verbs, resources, or apiGroups.
// Wildcards defeat least privilege and are the most common way an
// innocuous-looking role silently becomes cluster-admin-adjacent.
func checkWildcards(c *Cluster) []Risk {
	var rs []Risk
	for _, key := range sortedRoleKeys(c) {
		role := c.Roles[key]
		for i, rule := range role.Rules {
			var dims []string
			if hasWildcard(rule.Verbs) {
				dims = append(dims, "verbs")
			}
			if hasWildcard(rule.Resources) {
				dims = append(dims, "resources")
			}
			if hasWildcard(rule.APIGroups) {
				dims = append(dims, "apiGroups")
			}
			if len(dims) == 0 {
				continue
			}
			rs = append(rs, Risk{
				RuleID:      "DS-RAT-RBAC-001",
				Severity:    wildcardSeverity(dims),
				Title:       fmt.Sprintf("Wildcard grant in %s", roleLabel(role)),
				Description: fmt.Sprintf("rule %d uses '*' for %s", i, strings.Join(dims, ", ")),
				Resource:    roleLabel(role),
				Remediation: "Replace '*' with the specific verbs/resources/apiGroups actually required (see least-privilege report).",
				References:  []string{refK8sHarden, refNISTac6},
				Meta:        map[string]string{"wildcardDimensions": strings.Join(dims, ","), "role": role.Name},
			})
		}
	}
	return rs
}

// --- Grant-level checks --------------------------------------------------

// checkRiskyVerbs flags any grant carrying escalate/bind/impersonate.
func checkRiskyVerbs(g *Graph) []Risk {
	var rs []Risk
	for _, gr := range g.Grants {
		for _, rule := range gr.Role.Rules {
			for verb, meta := range riskyVerbs {
				if contains(rule.Verbs, verb) {
					rs = append(rs, subjectRisk(gr, meta.rule, meta.sev,
						fmt.Sprintf("%s %s", subjectLabel(gr.Subject), meta.why),
						"Remove the '"+verb+"' verb unless this identity is a trusted controller; prefer a narrowly scoped role.",
						map[string]string{"verb": verb, "role": gr.Role.Name}))
				}
			}
		}
	}
	return dedupe(rs)
}

// checkClusterAdmin flags subjects bound to cluster-admin or to the
// system:masters group (which bypasses RBAC entirely).
func checkClusterAdmin(g *Graph) []Risk {
	var rs []Risk
	for _, gr := range g.Grants {
		adminByRole := gr.Role.ClusterScoped && gr.Role.Name == "cluster-admin"
		adminByMaster := gr.Subject.Kind == "Group" && gr.Subject.Name == "system:masters"
		if !adminByRole && !adminByMaster {
			continue
		}
		how := "bound to cluster-admin"
		if adminByMaster {
			how = "member of system:masters (bypasses RBAC entirely)"
		}
		rs = append(rs, subjectRisk(gr, "DS-RAT-RBAC-002", engine.SeverityCritical,
			fmt.Sprintf("%s is %s", subjectLabel(gr.Subject), how),
			"Grant a scoped role instead of cluster-admin; reserve cluster-admin for break-glass with time-boxed, audited elevation.",
			map[string]string{"role": gr.Role.Name}))
	}
	return dedupe(rs)
}

// checkSecretReaders flags get/list/watch on secrets — reading secrets includes
// reading other service accounts' tokens, a direct path to impersonating them.
func checkSecretReaders(g *Graph) []Risk {
	return verbResourceCheck(g, "DS-RAT-RBAC-006", engine.SeverityHigh,
		[]string{"get", "list", "watch"}, "secrets",
		"can read Secrets (including ServiceAccount tokens)",
		"Scope secret access to named secrets (resourceNames) or remove it; treat secret read as token theft.")
}

// checkExec flags create on pods/exec and pods/attach — a shell inside any pod,
// i.e. code execution as that pod's identity.
func checkExec(g *Graph) []Risk {
	var rs []Risk
	rs = append(rs, verbResourceCheck(g, "DS-RAT-RBAC-007", engine.SeverityHigh,
		[]string{"create", "*"}, "pods/exec",
		"can exec into running pods (code execution as the pod)",
		"Remove pods/exec unless required for support tooling; audit and time-box it.")...)
	rs = append(rs, verbResourceCheck(g, "DS-RAT-RBAC-007", engine.SeverityHigh,
		[]string{"create", "*"}, "pods/attach",
		"can attach to running pods (code execution as the pod)",
		"Remove pods/attach unless required; audit and time-box it.")...)
	return dedupe(rs)
}

// checkProxyAndNodes flags proxy subresources and node access, which can reach
// the kubelet API and, from there, every pod on a node (host-level reach).
func checkProxyAndNodes(g *Graph) []Risk {
	var rs []Risk
	for _, res := range []string{"nodes/proxy", "pods/proxy", "services/proxy", "nodes"} {
		rs = append(rs, verbResourceCheck(g, "DS-RAT-RBAC-008", engine.SeverityHigh,
			[]string{"get", "create", "*"}, res,
			"has proxy/node access ("+res+"), which can reach the kubelet and node-level resources",
			"Remove proxy/node access from workload identities; restrict to the control plane.")...)
	}
	return dedupe(rs)
}

// checkTokenMint flags the ability to mint ServiceAccount tokens
// (serviceaccounts/token, tokenrequests) — on-demand credentials for any SA.
func checkTokenMint(g *Graph) []Risk {
	var rs []Risk
	for _, res := range []string{"serviceaccounts/token", "tokenrequests"} {
		rs = append(rs, verbResourceCheck(g, "DS-RAT-RBAC-009", engine.SeverityHigh,
			[]string{"create", "*"}, res,
			"can mint ServiceAccount tokens ("+res+")",
			"Restrict token minting to controllers that require it; it is equivalent to holding every SA's credentials.")...)
	}
	return dedupe(rs)
}

// checkCSRSigning flags the certificate-signing path (create CSRs + approve/sign),
// which can forge client certs for arbitrary users/groups — including masters.
func checkCSRSigning(g *Graph) []Risk {
	var rs []Risk
	rs = append(rs, verbResourceCheck(g, "DS-RAT-RBAC-010", engine.SeverityHigh,
		[]string{"create", "*"}, "certificatesigningrequests",
		"can create CSRs",
		"Only allow CSR creation where required; combined with approve/sign it forges arbitrary client certificates.")...)
	rs = append(rs, verbResourceCheck(g, "DS-RAT-RBAC-010", engine.SeverityHigh,
		[]string{"update", "*"}, "certificatesigningrequests/approval",
		"can approve CSRs",
		"Restrict CSR approval to the control plane.")...)
	rs = append(rs, verbResourceCheck(g, "DS-RAT-RBAC-010", engine.SeverityHigh,
		[]string{"create", "*"}, "signers",
		"can act as a CSR signer",
		"Restrict signer access to the control plane.")...)
	return dedupe(rs)
}

// checkWorkloadCreation flags create/patch on pods and pod-templating controllers.
// Pod creation lets a subject choose any ServiceAccount and (absent admission)
// any securityContext — the foundation of most container escapes.
func checkWorkloadCreation(g *Graph) []Risk {
	var rs []Risk
	for _, res := range []string{"pods", "deployments", "daemonsets", "statefulsets", "replicasets", "jobs", "cronjobs"} {
		rs = append(rs, verbResourceCheck(g, "DS-RAT-RBAC-013", engine.SeverityMedium,
			[]string{"create", "*"}, res,
			"can create workloads ("+res+"), and thus choose the ServiceAccount and securityContext they run with",
			"Pair workload-create access with a Phase 4 admission policy that blocks privileged/hostPath/hostNetwork pods.")...)
	}
	return dedupe(rs)
}

// checkBroadSubjects flags grants to the everyone-groups (system:authenticated,
// system:anonymous) or wildcard subjects, which spray a permission across the
// whole cluster's identities.
func checkBroadSubjects(g *Graph) []Risk {
	var rs []Risk
	broad := map[string]bool{"system:authenticated": true, "system:anonymous": true, "system:unauthenticated": true, "*": true}
	for _, gr := range g.Grants {
		if gr.Subject.Kind == "Group" && broad[gr.Subject.Name] {
			rs = append(rs, subjectRisk(gr, "DS-RAT-RBAC-019", engine.SeverityHigh,
				fmt.Sprintf("Role %q granted to broad group %q", gr.Role.Name, gr.Subject.Name),
				"Never bind roles to system:authenticated/anonymous; scope to specific ServiceAccounts or groups.",
				map[string]string{"group": gr.Subject.Name, "role": gr.Role.Name}))
		}
	}
	return dedupe(rs)
}

// checkDangling flags bindings whose roleRef points at a non-existent role. They
// grant nothing today but silently start granting if a role with that name is
// later created — a footgun and a sign of drift.
func checkDangling(g *Graph) []Risk {
	var rs []Risk
	for _, b := range g.dangling {
		rs = append(rs, Risk{
			RuleID:      "DS-RAT-RBAC-011",
			Severity:    engine.SeverityLow,
			Title:       fmt.Sprintf("Dangling binding %q references missing %s %q", b.Name, b.RoleRef.Kind, b.RoleRef.Name),
			Description: "The referenced role does not exist in the analyzed set; the binding grants nothing now but will if that name is later created.",
			Resource:    bindingLabel(b),
			Remediation: "Delete the binding or point it at an existing role.",
			References:  []string{refK8sRBAC},
			Meta:        map[string]string{"roleRef": b.RoleRef.Kind + "/" + b.RoleRef.Name},
		})
	}
	return rs
}

// checkDefaultSA flags workloads running as the namespace "default" SA and SAs
// that automount tokens — the default posture that hands a token to code that
// usually needs none.
func checkDefaultSA(c *Cluster) []Risk {
	var rs []Risk
	for _, p := range c.Pods {
		if p.effectiveSA() == "default" {
			rs = append(rs, Risk{
				RuleID:      "DS-RAT-RBAC-012",
				Severity:    engine.SeverityMedium,
				Title:       fmt.Sprintf("Pod %s/%s uses the default ServiceAccount", p.Namespace, p.Name),
				Description: "The default SA is shared and easy to over-grant; a token is mounted unless explicitly disabled.",
				Resource:    p.Namespace + "/" + p.Name,
				Remediation: "Assign a dedicated ServiceAccount and set automountServiceAccountToken: false where no API access is needed.",
				References:  []string{refK8sHarden},
				Meta:        map[string]string{"namespace": p.Namespace, "pod": p.Name},
			})
		}
	}
	for _, sa := range sortedSAs(c) {
		if sa.Name == "default" || !sa.automounts() {
			continue
		}
		rs = append(rs, Risk{
			RuleID:      "DS-RAT-RBAC-012",
			Severity:    engine.SeverityLow,
			Title:       fmt.Sprintf("ServiceAccount %s/%s automounts a token", sa.Namespace, sa.Name),
			Description: "automountServiceAccountToken is not disabled; a token is mounted into every pod using this SA.",
			Resource:    sa.Namespace + "/" + sa.Name,
			Remediation: "Set automountServiceAccountToken: false unless the workload calls the Kubernetes API.",
			References:  []string{refK8sHarden},
			Meta:        map[string]string{"namespace": sa.Namespace, "serviceAccount": sa.Name},
		})
	}
	return rs
}

// checkDockerHosts flags the local-daemon privilege surface: docker-group members
// (root-equivalent), mounted daemon sockets (host takeover from a container), and
// non-rootless daemons.
func checkDockerHosts(c *Cluster) []Risk {
	var rs []Risk
	for _, h := range c.DockerHosts {
		for _, member := range sortedStrings(h.DockerGroupMembers) {
			rs = append(rs, Risk{
				RuleID:      "DS-RAT-RBAC-015",
				Severity:    engine.SeverityHigh,
				Title:       fmt.Sprintf("%q is in the docker group on %s", member, h.Name),
				Description: "docker group membership is equivalent to root: any member can start a privileged container that mounts the host filesystem.",
				Subject:     "User/" + member,
				Resource:    h.Name,
				Remediation: "Remove users from the docker group; use rootless Docker or sudo-audited access instead.",
				References:  []string{refDockerSock},
				Meta:        map[string]string{"host": h.Name, "user": member},
			})
		}
		for _, m := range h.SocketMounts {
			rs = append(rs, Risk{
				RuleID:      "DS-RAT-RBAC-016",
				Severity:    engine.SeverityCritical,
				Title:       fmt.Sprintf("Container %q mounts the Docker socket (%s)", m.Container, m.Path),
				Description: "A mounted Docker daemon socket gives the container full control of every container on the host — a container escape by design.",
				Resource:    m.Container,
				Remediation: "Never bind-mount docker.sock into containers; use a scoped API proxy or rootless/socket-less tooling.",
				References:  []string{refDockerSock, refMitreEscape},
				Meta:        map[string]string{"host": h.Name, "container": m.Container, "path": m.Path},
			})
		}
		if !h.Rootless {
			rs = append(rs, Risk{
				RuleID:      "DS-RAT-RBAC-017",
				Severity:    engine.SeverityInfo,
				Title:       fmt.Sprintf("Docker daemon on %s is not rootless", h.Name),
				Description: "A root daemon means a container breakout is a host-root breakout.",
				Resource:    h.Name,
				Remediation: "Adopt rootless Docker where feasible to shrink the blast radius of an escape.",
				References:  []string{refDockerSock},
				Meta:        map[string]string{"host": h.Name},
			})
		}
	}
	return rs
}

// --- Shared check plumbing -----------------------------------------------

// verbResourceCheck flags every grant whose role permits any of verbs on
// resource. The resource string is matched against the rule's resources with
// wildcard support, so "pods/exec" also matches a "*" resource grant.
func verbResourceCheck(g *Graph, ruleID string, sev engine.Severity, verbs []string, resource, why, remediation string) []Risk {
	var rs []Risk
	for _, gr := range g.Grants {
		for _, rule := range gr.Role.Rules {
			if resourceMatches(rule, resource) && anyVerb(rule, verbs) {
				rs = append(rs, subjectRisk(gr, ruleID, sev,
					fmt.Sprintf("%s %s", subjectLabel(gr.Subject), why),
					remediation,
					map[string]string{"resource": resource, "role": gr.Role.Name}))
				break
			}
		}
	}
	return dedupe(rs)
}

// subjectRisk builds a subject-attributed Risk with consistent scope metadata.
func subjectRisk(gr Grant, ruleID string, sev engine.Severity, title, remediation string, meta map[string]string) Risk {
	scope := "cluster-wide"
	if gr.Namespace != "" {
		scope = "namespace " + gr.Namespace
	}
	if meta == nil {
		meta = map[string]string{}
	}
	meta["scope"] = scope
	meta["binding"] = gr.Binding.Name
	return Risk{
		RuleID:      ruleID,
		Severity:    sev,
		Title:       title,
		Description: fmt.Sprintf("via binding %q → %s %q (%s)", gr.Binding.Name, gr.Role.roleKind(), gr.Role.Name, scope),
		Subject:     gr.Subject.key(),
		Resource:    gr.Role.Name,
		Remediation: remediation,
		References:  []string{refK8sHarden, refMitrePrivEsc},
		Meta:        meta,
	}
}

// --- Predicates and formatting helpers -----------------------------------

func hasWildcard(xs []string) bool { return contains(xs, "*") && len(xs) > 0 }

func wildcardSeverity(dims []string) engine.Severity {
	// Wildcard verbs are the sharpest edge; a resources+verbs combo is effectively
	// admin over a group. Weight accordingly.
	if len(dims) >= 2 {
		return engine.SeverityHigh
	}
	return engine.SeverityMedium
}

func anyVerb(r PolicyRule, verbs []string) bool {
	for _, v := range verbs {
		if contains(r.Verbs, v) {
			return true
		}
	}
	return false
}

// resourceMatches reports whether a rule covers resource, honoring "*" and the
// "resource" ⊂ "resource/subresource" relationship (a grant on "pods" does not
// imply "pods/exec", but a "*" grant covers both).
func resourceMatches(r PolicyRule, resource string) bool {
	for _, res := range r.Resources {
		if res == "*" || res == resource {
			return true
		}
	}
	return false
}

func (r *Role) roleKind() string {
	if r.ClusterScoped {
		return "ClusterRole"
	}
	return "Role"
}

func roleLabel(r *Role) string {
	if r.ClusterScoped {
		return "ClusterRole/" + r.Name
	}
	return "Role/" + r.Namespace + "/" + r.Name
}

func bindingLabel(b *Binding) string {
	if b.ClusterScoped {
		return "ClusterRoleBinding/" + b.Name
	}
	return "RoleBinding/" + b.Namespace + "/" + b.Name
}

func subjectLabel(s Subject) string {
	if s.Kind == "ServiceAccount" {
		return fmt.Sprintf("ServiceAccount %s/%s", s.Namespace, s.Name)
	}
	return fmt.Sprintf("%s %q", s.Kind, s.Name)
}

// dedupe removes identical (RuleID, Subject, Resource, Title) risks that arise
// when several rules in one role trip the same check.
func dedupe(rs []Risk) []Risk {
	seen := map[string]struct{}{}
	out := rs[:0]
	for _, r := range rs {
		k := r.RuleID + "|" + r.Subject + "|" + r.Resource + "|" + r.Title
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, r)
	}
	return out
}

// --- Deterministic iteration helpers -------------------------------------

func sortedRoleKeys(c *Cluster) []string {
	keys := make([]string, 0, len(c.Roles))
	for k := range c.Roles {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedSAs(c *Cluster) []*ServiceAccount {
	out := make([]*ServiceAccount, 0, len(c.ServiceAccounts))
	for _, sa := range c.ServiceAccounts {
		out = append(out, sa)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Namespace != out[j].Namespace {
			return out[i].Namespace < out[j].Namespace
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func sortedStrings(xs []string) []string {
	out := append([]string(nil), xs...)
	sort.Strings(out)
	return out
}
