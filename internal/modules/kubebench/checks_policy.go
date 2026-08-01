package kubebench

import (
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/compliance"
)

// --- Section 5 checks: policies (RBAC & Pod Security) ----------------------
//
// These evaluate cluster-level authorization and workload-isolation posture
// from the reduced RBAC / Pod-Security / network-policy evidence. Each check
// degrades to INFO when its evidence was not collected, and lists offenders
// deterministically (sorted) so output is stable.

// check511ClusterAdmin flags cluster-admin bindings beyond the built-in
// system:masters binding. Any ServiceAccount or ordinary user/group granted
// cluster-admin is an unbounded-superuser risk.
func check511ClusterAdmin(e *Evidence) compliance.Assessment {
	if len(e.RBAC.ClusterRoleBindings) == 0 {
		return info("no ClusterRoleBindings collected; cannot assess")
	}
	var offenders []string
	for _, b := range e.RBAC.ClusterRoleBindings {
		if !refersTo(b.RoleRef, "cluster-admin") {
			continue
		}
		for _, s := range b.Subjects {
			if s.Kind == "Group" && s.Name == "system:masters" {
				continue // the expected built-in binding
			}
			offenders = append(offenders, b.Name+"→"+s.Kind+"/"+s.Name)
		}
	}
	if len(offenders) == 0 {
		return pass("cluster-admin is bound only to system:masters")
	}
	sort.Strings(offenders)
	joined := strings.Join(offenders, "; ")
	return fail("cluster-admin is granted to additional subjects: "+joined, joined)
}

// check513Wildcards flags roles that use "*" in apiGroups, resources, or verbs.
func check513Wildcards(e *Evidence) compliance.Assessment {
	if len(e.RBAC.Roles) == 0 {
		return info("no Roles/ClusterRoles collected; cannot assess")
	}
	var offenders []string
	for _, r := range e.RBAC.Roles {
		for _, rule := range r.Rules {
			if hasWildcard(rule.APIGroups) || hasWildcard(rule.Resources) || hasWildcard(rule.Verbs) {
				offenders = append(offenders, r.Name)
				break
			}
		}
	}
	if len(offenders) == 0 {
		return pass("no wildcard permissions in collected roles")
	}
	sort.Strings(offenders)
	joined := strings.Join(offenders, "; ")
	return fail("wildcard permissions found in roles: "+joined, joined)
}

// check515DefaultSA flags default ServiceAccounts that still automount tokens.
func check515DefaultSA(e *Evidence) compliance.Assessment {
	if len(e.RBAC.ServiceAccounts) == 0 {
		return info("no ServiceAccounts collected; cannot assess")
	}
	var offenders []string
	seenDefault := false
	for _, sa := range e.RBAC.ServiceAccounts {
		if sa.Name != "default" {
			continue
		}
		seenDefault = true
		if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
			offenders = append(offenders, sa.Namespace+"/default")
		}
	}
	if !seenDefault {
		return info("no default ServiceAccounts present in the collected set")
	}
	if len(offenders) == 0 {
		return pass("default ServiceAccounts disable token automount")
	}
	sort.Strings(offenders)
	joined := strings.Join(offenders, "; ")
	return fail("default ServiceAccounts automount tokens: "+joined, joined)
}

// check522PodSecurity requires Pod Security Admission enabled and workload
// namespaces enforcing at least the baseline level.
func check522PodSecurity(e *Evidence) compliance.Assessment {
	if !e.PodSecurity.AdmissionEnabled && len(e.PodSecurity.NamespaceEnforce) == 0 {
		if len(e.Namespaces) == 0 {
			return info("no Pod Security posture collected; cannot assess")
		}
		return fail("Pod Security Admission is not enabled", "admission disabled")
	}
	var offenders []string
	for _, ns := range e.Namespaces {
		level := e.PodSecurity.NamespaceEnforce[ns]
		if level != "baseline" && level != "restricted" {
			offenders = append(offenders, ns+"="+orUnset(level))
		}
	}
	if len(offenders) == 0 {
		return pass("all workload namespaces enforce baseline/restricted Pod Security")
	}
	sort.Strings(offenders)
	joined := strings.Join(offenders, "; ")
	return fail("namespaces without an enforced baseline/restricted level: "+joined, joined)
}

// check532NetworkPolicies requires every workload namespace to have a policy.
func check532NetworkPolicies(e *Evidence) compliance.Assessment {
	if len(e.Namespaces) == 0 {
		return info("no workload namespaces collected; cannot assess")
	}
	have := map[string]bool{}
	for _, ns := range e.NetworkPolicyNamespaces {
		have[ns] = true
	}
	var offenders []string
	for _, ns := range e.Namespaces {
		if !have[ns] {
			offenders = append(offenders, ns)
		}
	}
	if len(offenders) == 0 {
		return pass("every workload namespace has at least one NetworkPolicy")
	}
	sort.Strings(offenders)
	joined := strings.Join(offenders, "; ")
	return fail("namespaces without a NetworkPolicy: "+joined, joined)
}

// check574DefaultNamespace flags workloads placed in the default namespace.
func check574DefaultNamespace(e *Evidence) compliance.Assessment {
	if len(e.Namespaces) == 0 {
		return info("no workload namespaces collected; cannot assess")
	}
	for _, ns := range e.Namespaces {
		if ns == "default" {
			return fail("the default namespace is used for workloads", "default")
		}
	}
	return pass("the default namespace is not used for workloads")
}

// --- small predicates ------------------------------------------------------

func refersTo(roleRef, name string) bool {
	return strings.EqualFold(roleRef, name) || strings.HasSuffix(roleRef, "/"+name)
}

func hasWildcard(vals []string) bool {
	for _, v := range vals {
		if v == "*" {
			return true
		}
	}
	return false
}

func orUnset(s string) string {
	if s == "" {
		return "unset"
	}
	return s
}
