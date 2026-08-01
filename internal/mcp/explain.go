package mcp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Explanation & remediation planning (the AI-age core) ----------------
//
// These functions turn a Finding into something an agent can reason about:
// a category, why it matters, machine-consumable remediation steps, an effort
// estimate, and any framework mappings (ATT&CK / CIS) carried on the finding.
// Everything here is a pure function of the finding — no model, no clock, no
// network — so the "intelligence" layer is fully deterministic and testable. A
// model, if present, phrases or reprioritizes on top; it never gates this.

// ruleClass describes a family of rules keyed by RuleID prefix. It supplies the
// human "why" and a sane default remediation when a finding carries none.
type ruleClass struct {
	category     string
	whyItMatters string
	defaultFix   string
	effort       string // low | medium | high — relative work to remediate
}

// classes maps a DS-<AREA> prefix to its rule class. Unknown prefixes fall back
// to a generic class, so a module added later still explains reasonably.
var classes = map[string]ruleClass{
	"DS-RAT-DF": {"dockerfile-hygiene",
		"Dockerfile misconfigurations bake risk into every image built from them — an unpinned base or a leaked build secret propagates to all downstream deployments.",
		"Edit the Dockerfile: pin base images by digest, drop privileges, and remove build-time secrets.", "low"},
	"DS-RAT-IMG": {"image-configuration",
		"The built image's config and layers define its runtime attack surface (user, capabilities, exposed ports, setuid binaries) regardless of how it was built.",
		"Rebuild with a non-root user, minimal capabilities, and no setuid binaries; strip unnecessary tooling.", "medium"},
	"DS-RAT-VULN": {"known-vulnerability",
		"A component matches a published advisory. If the vulnerable code path is reachable, an attacker with a matching exploit can compromise the container.",
		"Upgrade the affected package to a fixed version; if none exists, apply a VEX exception with justification and expiry.", "medium"},
	"DS-RAT-SBOM": {"inventory",
		"Inventory findings describe what is present, not a defect. They matter because you cannot defend components you do not know you ship.",
		"No action required; use the inventory to drive vulnerability and license queries.", "low"},
	"DS-RAT-SEC": {"secret-exposure",
		"A credential embedded in an image is readable by anyone who can pull it. Rotation is mandatory: deleting the layer does not un-leak an already-pushed secret.",
		"Rotate and revoke the exposed credential immediately, then remove it from the build and inject it at runtime instead.", "high"},
	"DS-RAT-CIS": {"benchmark",
		"CIS benchmark deviations are the baseline hardening auditors and attackers both check first.",
		"Apply the CIS-recommended setting for this control.", "medium"},
	"DS-RAT-K8S": {"benchmark",
		"Kubernetes benchmark deviations widen the blast radius of a single compromised pod across the cluster.",
		"Apply the recommended Kubernetes hardening for this control.", "medium"},
	"DS-RAT-RBAC": {"identity-permissions",
		"Excess permissions turn a single compromised identity into lateral movement and privilege escalation.",
		"Reduce the role to least privilege based on observed usage; remove wildcard verbs and cluster-admin bindings.", "medium"},
	"DS-RAT-ATK": {"attack-path",
		"A simulated adversary technique had no compensating control, so a real one would likely succeed.",
		"Add or fix the control that would detect or block this technique.", "high"},
	"DS-RAT-SIG": {"supply-chain-trust",
		"Unsigned or unverifiable artifacts break the chain of custody: you cannot prove what you are running is what you built.",
		"Sign the artifact and verify signatures/attestations in the admission path.", "medium"},
	"DS-RAT-NET": {"network-exposure",
		"Overly broad network reachability lets a compromised workload talk to things it never should.",
		"Constrain egress/ingress with a default-deny policy and explicit allowlists.", "medium"},
	"DS-RAT-PLT": {"platform",
		"Platform findings concern how the tool itself is deployed and integrated.",
		"Follow the platform hardening guidance for this control.", "low"},
}

var genericClass = ruleClass{
	category:     "general",
	whyItMatters: "This finding represents a deviation from a security best practice.",
	defaultFix:   "Review the finding detail and apply the recommended change.",
	effort:       "medium",
}

func classify(ruleID string) ruleClass {
	for prefix, c := range classes {
		if strings.HasPrefix(ruleID, prefix) {
			return c
		}
	}
	return genericClass
}

// Explanation is the machine-and-human view of a single finding.
type Explanation struct {
	RuleID         string   `json:"rule_id"`
	Module         string   `json:"module"`
	Severity       string   `json:"severity"`
	SeverityRank   int      `json:"severity_rank"` // 0..5, higher = worse
	Category       string   `json:"category"`
	Title          string   `json:"title"`
	Resource       string   `json:"resource,omitempty"`
	WhyItMatters   string   `json:"why_it_matters"`
	Detail         string   `json:"detail,omitempty"`
	Remediation    []string `json:"remediation"`
	HasRemediation bool     `json:"has_remediation"`
	Effort         string   `json:"effort"`
	Frameworks     []string `json:"frameworks,omitempty"` // extracted ATT&CK/CIS/NIST refs
	References     []string `json:"references,omitempty"`
	Confidence     string   `json:"confidence"`
}

// Explain projects a finding into a structured explanation. It is deterministic
// and self-contained: no lookups outside the finding and the static rule-class
// table.
func Explain(f engine.Finding) Explanation {
	c := classify(f.RuleID)
	steps := remediationSteps(f, c)
	return Explanation{
		RuleID:         f.RuleID,
		Module:         f.Module,
		Severity:       f.Severity.String(),
		SeverityRank:   int(f.Severity),
		Category:       c.category,
		Title:          f.Title,
		Resource:       f.Resource,
		WhyItMatters:   c.whyItMatters,
		Detail:         f.Description,
		Remediation:    steps,
		HasRemediation: strings.TrimSpace(f.Remediation) != "",
		Effort:         c.effort,
		Frameworks:     frameworks(f),
		References:     f.References,
		Confidence:     confidence(f),
	}
}

// remediationSteps prefers the finding's own remediation, split into actionable
// steps; if it carries none, it falls back to the rule class's default fix so an
// agent always receives something to act on.
func remediationSteps(f engine.Finding, c ruleClass) []string {
	rem := strings.TrimSpace(f.Remediation)
	if rem == "" {
		return []string{c.defaultFix}
	}
	// Split on sentence and line boundaries into discrete steps.
	fields := strings.FieldsFunc(rem, func(r rune) bool { return r == '\n' || r == ';' })
	var steps []string
	for _, s := range fields {
		if s = strings.TrimSpace(s); s != "" {
			steps = append(steps, s)
		}
	}
	if len(steps) == 0 {
		steps = []string{rem}
	}
	return steps
}

// frameworks extracts security-framework identifiers (ATT&CK technique ids, CIS,
// NIST) from a finding's references and metadata so an agent can pivot to the
// control catalog. Sorted and de-duplicated for stable output.
func frameworks(f engine.Finding) []string {
	seen := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
	}
	for _, r := range f.References {
		up := strings.ToUpper(r)
		switch {
		case strings.Contains(up, "ATTACK.MITRE") || strings.Contains(up, "ATT&CK"):
			add(r)
		case strings.Contains(up, "CIS") || strings.Contains(up, "NIST"):
			add(r)
		}
	}
	for k, v := range f.Metadata {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "attack") || strings.Contains(lk, "technique") ||
			strings.Contains(lk, "cis") || strings.Contains(lk, "nist") || strings.Contains(lk, "cwe") {
			add(k + "=" + v)
		}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// confidence is a coarse, deterministic signal derived from how much evidence
// the finding carries. It is intentionally simple — a hint, not a probability.
func confidence(f engine.Finding) string {
	if f.Location != nil && f.Location.StartLine > 0 {
		return "high" // pinned to an exact line
	}
	if f.Resource != "" || len(f.Metadata) > 0 {
		return "medium"
	}
	return "low"
}

// --- Remediation plan (security copilot) ---------------------------------

// PlanAction is one prioritized step in a remediation plan.
type PlanAction struct {
	Priority   int      `json:"priority"`
	Severity   string   `json:"severity"`
	RuleID     string   `json:"rule_id"`
	Module     string   `json:"module,omitempty"`
	Resource   string   `json:"resource,omitempty"`
	Title      string   `json:"title"`
	Steps      []string `json:"steps"`
	Rationale  string   `json:"rationale"`
	Effort     string   `json:"effort"`
	References []string `json:"references,omitempty"`
}

// RemediationPlan is a prioritized, explained action plan an agent or human can
// execute top-to-bottom. It is the deterministic data behind the "security
// copilot": a model may reword or regroup it, but the ordering and content are
// reproducible from the findings alone.
type RemediationPlan struct {
	Target  string         `json:"target"`
	Total   int            `json:"total"`
	Counts  map[string]int `json:"counts"`
	Actions []PlanAction   `json:"actions"`
	Summary string         `json:"summary"`
}

// BuildPlan turns findings into a prioritized plan: most-severe first, then by
// rule id for stability. Priority numbers are assigned after sorting so they
// read 1..N top-to-bottom.
func BuildPlan(target string, findings []engine.Finding) RemediationPlan {
	sorted := make([]engine.Finding, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Severity != sorted[j].Severity {
			return sorted[i].Severity > sorted[j].Severity
		}
		if sorted[i].RuleID != sorted[j].RuleID {
			return sorted[i].RuleID < sorted[j].RuleID
		}
		return sorted[i].Resource < sorted[j].Resource
	})

	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	actions := make([]PlanAction, 0, len(sorted))
	for i, f := range sorted {
		counts[f.Severity.String()]++
		ex := Explain(f)
		actions = append(actions, PlanAction{
			Priority:   i + 1,
			Severity:   f.Severity.String(),
			RuleID:     f.RuleID,
			Module:     f.Module,
			Resource:   f.Resource,
			Title:      f.Title,
			Steps:      ex.Remediation,
			Rationale:  ex.WhyItMatters,
			Effort:     ex.Effort,
			References: f.References,
		})
	}
	return RemediationPlan{
		Target:  target,
		Total:   len(sorted),
		Counts:  counts,
		Actions: actions,
		Summary: planSummary(target, counts),
	}
}

// planSummary is a one-line human headline for the plan.
func planSummary(target string, counts map[string]int) string {
	if total := counts["CRITICAL"] + counts["HIGH"] + counts["MEDIUM"] + counts["LOW"] + counts["INFO"]; total == 0 {
		return fmt.Sprintf("%s: no findings — nothing to remediate.", target)
	}
	return fmt.Sprintf("%s: fix %d critical and %d high first, then %d medium, %d low.",
		target, counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"])
}
