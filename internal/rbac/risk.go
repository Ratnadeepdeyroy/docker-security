package rbac

import (
	"sort"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// This file defines the Risk value that every analysis pass emits, plus the
// deterministic ordering the whole package guarantees. Keeping the risk shape
// and its sort in one place means the module wrapper and the CLI command render
// identical, stable output from the same analysis.

// --- Risk ----------------------------------------------------------------

// Risk is one identity/RBAC problem found in the cluster. It is engine-agnostic
// (no import of the Finding type in the pure model beyond severity), so the
// analysis library can be tested and reused without the module layer. The rbac
// engine module maps Risk directly onto engine.Finding.
type Risk struct {
	RuleID      string
	Severity    engine.Severity
	Title       string
	Description string
	// Subject is the principal at fault (subject key) when applicable; Resource
	// is the object at fault (role/binding name) otherwise. At least one is set.
	Subject     string
	Resource    string
	Remediation string
	References  []string
	// Path, when set, is a human-readable escalation chain (pod → … →
	// cluster-admin) that justifies an escalation finding.
	Path []string
	// Meta carries structured, machine-consumable context for agent remediation
	// (the "explain & auto-remediate" mandate): the exact verb/resource that
	// triggered the rule, the namespace, and so on.
	Meta map[string]string
}

// sortRisks orders risks deterministically: by RuleID, then Subject, then
// Resource, then Title. Analysis walks Go maps (unordered), so without this the
// output — and therefore the golden test — would flake.
func sortRisks(rs []Risk) {
	sort.Slice(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		return a.Title < b.Title
	})
}

// --- Standard references -------------------------------------------------
//
// Centralized so every rule cites the same authorities and we avoid typo drift.

var (
	refK8sRBAC      = "https://kubernetes.io/docs/reference/access-authn-authz/rbac/"
	refK8sHarden    = "https://kubernetes.io/docs/concepts/security/rbac-good-practices/"
	refMitrePrivEsc = "https://attack.mitre.org/tactics/TA0004/"
	refMitreEscape  = "https://attack.mitre.org/techniques/T1611/"
	refNISTac6      = "https://csrc.nist.gov/projects/risk-management/sp800-53-controls (AC-6 Least Privilege)"
	refDockerSock   = "https://docs.docker.com/engine/security/#docker-daemon-attack-surface"
)
