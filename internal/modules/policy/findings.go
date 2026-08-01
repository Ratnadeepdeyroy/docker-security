package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/policy"
)

// --- Projecting a decision into findings -----------------------------------
//
// The engine returns a single Result; a scan report wants findings. Each firing
// becomes one finding so it sorts and renders alongside every other module's
// output, and a machine-readable verdict finding summarizes the decision for a
// gate to key off. This is the PolicyReport-style output the market expects,
// expressed in the tool's native Finding model.

// projectFindings turns a policy Result (and optional explanation) into findings.
// It uses the same decision-consistent accessors the engine exposes, so a
// DS-RAT-POL-100 violation is never emitted for a rule an allow override neutralized.
func projectFindings(res *policy.Result, ex *policy.Explanation, resource string) []engine.Finding {
	out := []engine.Finding{verdictFinding(res, ex, resource)}

	for _, rr := range res.Denials() {
		out = append(out, ruleFinding(ruleViolation, engine.ParseSeverity(rr.Severity), "deny", rr, resource))
	}
	for _, rr := range res.Warnings() {
		out = append(out, ruleFinding(ruleWarning, engine.ParseSeverity(rr.Severity), "warn", rr, resource))
	}
	for _, rr := range res.WaivedRules() {
		out = append(out, ruleFinding(ruleWaived, engine.SeverityInfo, "waived", rr, resource))
	}
	return out
}

// verdictFinding is the machine-readable decision summary a gate keys off.
func verdictFinding(res *policy.Result, ex *policy.Explanation, resource string) engine.Finding {
	sev := engine.SeverityInfo
	if res.Decision == policy.DecisionDeny {
		sev = engine.SeverityHigh
	}
	meta := map[string]string{
		"decision":     string(res.Decision),
		"mode":         string(res.Mode),
		"policy":       res.Policy,
		"denial_count": itoa(len(res.Denials())),
	}
	// The explanation is attached only when the caller opted in (off by default);
	// an agent consumes it straight from finding metadata.
	if ex != nil {
		if data, err := json.Marshal(ex); err == nil {
			meta["explanation"] = string(data)
		}
	}
	return engine.Finding{
		RuleID:      ruleVerdict,
		Module:      moduleName,
		Severity:    sev,
		Title:       fmt.Sprintf("Policy decision: %s (%s)", up(string(res.Decision)), res.Policy),
		Description: verdictDescription(res),
		Resource:    resource,
		Metadata:    meta,
	}
}

// ruleFinding renders one rule outcome as a finding.
func ruleFinding(id string, sev engine.Severity, kind string, rr policy.RuleResult, resource string) engine.Finding {
	title := fmt.Sprintf("Policy %s: %s", kind, rr.RuleID)
	desc := rr.Message
	if desc == "" {
		desc = rr.Description
	}
	if rr.Error != "" {
		desc = "rule evaluation failed (fail-closed): " + rr.Error
	}
	meta := map[string]string{
		"rule":   rr.RuleID,
		"effect": string(rr.Effect),
	}
	if rr.Waived {
		meta["waiver_reason"] = rr.WaiverReason
	}
	return engine.Finding{
		RuleID:      id,
		Module:      moduleName,
		Severity:    sev,
		Title:       title,
		Description: desc,
		Resource:    resource,
		Remediation: rr.Remediation,
		References:  rr.References,
		Metadata:    meta,
	}
}

// verdictDescription is the one-line human summary for the verdict finding.
func verdictDescription(res *policy.Result) string {
	switch res.Decision {
	case policy.DecisionDeny:
		return fmt.Sprintf("%d rule(s) blocked admission under policy %q (mode: %s).",
			len(res.Denials()), res.Policy, res.Mode)
	case policy.DecisionWarn:
		return fmt.Sprintf("Admitted with %d warning(s) under policy %q.",
			len(res.Warnings()), res.Policy)
	default:
		return fmt.Sprintf("Admitted by policy %q with no violations.", res.Policy)
	}
}

// diag builds a module-diagnostic finding (not-configured, load-error).
func diag(id string, sev engine.Severity, title, desc, resource, remediation string) engine.Finding {
	return engine.Finding{
		RuleID:      id,
		Module:      moduleName,
		Severity:    sev,
		Title:       title,
		Description: desc,
		Resource:    resource,
		Remediation: remediation,
	}
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }

// up uppercases a decision string for display ("deny" -> "DENY").
func up(s string) string { return strings.ToUpper(s) }
