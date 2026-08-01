package compliance

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Engine projection -----------------------------------------------------
//
// This is the single seam where compliance meets the engine. dockerbench and
// kubebench both call Findings() so the Status→Severity mapping, rule-id
// scheme, and reference formatting live in exactly one place.

// severityFor maps a compliance status onto the engine's severity scale. Only
// actionable statuses (FAIL/WARN and manual INFO) become findings; PASS is not
// projected — a scan should not be buried under hundreds of "compliant" lines,
// and the full pass/fail evidence remains in the compliance.Report export.
func severityFor(s Status) (engine.Severity, bool) {
	switch s {
	case StatusFail:
		return engine.SeverityHigh, true
	case StatusWarn:
		return engine.SeverityMedium, true
	case StatusInfo:
		return engine.SeverityInfo, true
	default: // PASS, UNKNOWN
		return engine.SeverityInfo, false
	}
}

// Findings projects a report into engine findings for the given module. It
// emits one leading INFO summary (score + counts, always present so the module
// shows up in a scan even when fully compliant) followed by a finding per
// non-PASS control. Effective status is used so waived controls report as INFO
// with the waiver reason rather than as failures. Output order follows the
// report's deterministic control ordering.
func Findings(moduleName string, rep *Report) []engine.Finding {
	out := make([]engine.Finding, 0, len(rep.Results)+1)
	out = append(out, summaryFinding(moduleName, rep))

	for _, res := range rep.Results {
		eff := res.effectiveStatus()
		sev, emit := severityFor(eff)
		if !emit || eff == StatusPass {
			continue
		}
		c := res.Control
		desc := c.Description
		if res.Evidence != "" {
			desc = strings.TrimSpace(desc + " Observed: " + res.Evidence)
		}
		if res.Waived {
			desc = strings.TrimSpace(desc + " [WAIVED: " + res.WaiverReason + "]")
		}

		meta := map[string]string{
			"benchmark": rep.Benchmark,
			"control":   c.ID,
			"status":    res.Status.String(), // raw verdict, not the demoted one
			"level":     c.Level.String(),
			"section":   c.Section,
		}
		if res.Actual != "" {
			meta["observed"] = res.Actual
		}
		if res.Waived {
			meta["waived"] = "true"
		}
		if c.Fix != nil {
			// Surface the structured, agent-appliable fix as metadata so an
			// automation layer can consume it without re-parsing prose.
			meta["fix_kind"] = c.Fix.Kind
			meta["fix_target"] = c.Fix.Target
			meta["fix_snippet"] = c.Fix.Snippet
		}

		out = append(out, engine.Finding{
			RuleID:      ruleID(rep, c.ID),
			Module:      moduleName,
			Severity:    sev,
			Title:       fmt.Sprintf("[%s %s] %s", res.Status, c.ID, c.Title),
			Description: desc,
			Resource:    rep.Benchmark,
			Remediation: c.Remediation,
			References:  c.References(rep.Benchmark),
			Metadata:    meta,
		})
	}
	return out
}

// summaryFinding is an always-present INFO carrying the headline posture so the
// module is visible in a scan and the score is queryable by an agent.
func summaryFinding(moduleName string, rep *Report) engine.Finding {
	counts := rep.Counts()
	profile := rep.Profile
	if profile == "" {
		profile = "default"
	}
	return engine.Finding{
		RuleID:   "DS-RAT-CIS-SUMMARY",
		Module:   moduleName,
		Severity: engine.SeverityInfo,
		Title: fmt.Sprintf("%s: %d%% compliant (%d pass, %d fail, %d warn)",
			rep.Benchmark, rep.Score(), counts[StatusPass], counts[StatusFail], counts[StatusWarn]),
		Description: fmt.Sprintf("Assessed %d controls against %s v%s (profile %s).",
			len(rep.Results), rep.Benchmark, rep.Version, profile),
		Resource:   rep.Benchmark,
		References: frameworkRefs(rep),
		Metadata: map[string]string{
			"benchmark": rep.Benchmark,
			"version":   rep.Version,
			"profile":   profile,
			"score":     fmt.Sprintf("%d", rep.Score()),
			"pass":      fmt.Sprintf("%d", counts[StatusPass]),
			"fail":      fmt.Sprintf("%d", counts[StatusFail]),
			"warn":      fmt.Sprintf("%d", counts[StatusWarn]),
			"info":      fmt.Sprintf("%d", counts[StatusInfo]),
		},
	}
}

// ruleID builds the namespaced finding id, e.g. "DS-RAT-CIS-DOCKER-2.1". The DS-RAT-CIS-
// prefix is mandated by the phase handoff; the benchmark code disambiguates
// docker vs k8s control numbers that would otherwise collide.
func ruleID(rep *Report, controlID string) string {
	code := benchmarkCode(rep.Benchmark)
	return fmt.Sprintf("DS-RAT-CIS-%s-%s", strings.ToUpper(code), controlID)
}

// benchmarkCode derives a short slug from a benchmark name for rule ids.
func benchmarkCode(name string) string {
	l := strings.ToLower(name)
	switch {
	case strings.Contains(l, "kubernetes"):
		return "k8s"
	case strings.Contains(l, "docker"):
		return "docker"
	default:
		f := strings.Fields(l)
		if len(f) > 0 {
			return f[0]
		}
		return "bench"
	}
}

// frameworkRefs lists the frameworks this report's controls collectively cover,
// as References on the summary finding, so the "one scan, many audits" mapping
// is visible without opening every control.
func frameworkRefs(rep *Report) []string {
	controls := make([]Control, 0, len(rep.Results))
	for _, r := range rep.Results {
		controls = append(controls, r.Control)
	}
	cov := FrameworkCoverage(controls)
	out := make([]string, 0, len(cov))
	for _, fw := range SortedFrameworks(cov) {
		out = append(out, fmt.Sprintf("%s (%d controls)", fw, cov[fw]))
	}
	sort.Strings(out)
	return out
}
