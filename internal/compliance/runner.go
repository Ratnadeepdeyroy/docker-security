package compliance

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// Disposition is a control's resolved state per the satisfaction contract
// (COMPLIANCE_PLAN §3). No control may remain Unknown at release.
type Disposition string

const (
	DispSatisfied     Disposition = "Satisfied"
	DispFailed        Disposition = "Failed"
	DispWaived        Disposition = "Waived"
	DispNotApplicable Disposition = "NotApplicable"
	DispManual        Disposition = "Manual" // awaiting attestation
	DispUnknown       Disposition = "Unknown"
)

// Resolved reports whether a disposition counts toward coverage (anything but
// Unknown and un-attested Manual).
func (d Disposition) Resolved() bool {
	return d == DispSatisfied || d == DispFailed || d == DispWaived || d == DispNotApplicable
}

// Evidence is the machine-readable proof attached to every assessed control.
type Evidence struct {
	Check     string `json:"check,omitempty"`
	Observed  string `json:"observed"`
	Verdict   string `json:"verdict"`
	Timestamp string `json:"timestamp"`
	Tool      string `json:"tool"`
	Target    string `json:"target,omitempty"`
}

// ControlResult is one control's assessment across the run, including the
// crosswalk to every framework it satisfies.
type ControlResult struct {
	Framework   string              `json:"framework"`
	Version     string              `json:"version"`
	ID          string              `json:"id"`
	Title       string              `json:"title"`
	Assessment  string              `json:"assessment"`
	Disposition Disposition         `json:"disposition"`
	Evidence    Evidence            `json:"evidence"`
	MapsTo      map[string][]string `json:"maps_to,omitempty"`
	Remediation string              `json:"remediation,omitempty"`
}

// ComplianceReport is the full result of a compliance run.
type ComplianceReport struct {
	Target      string          `json:"target"`
	GeneratedAt string          `json:"generated_at"`
	ToolVersion string          `json:"tool_version"`
	Frameworks  []string        `json:"frameworks"`
	Results     []ControlResult `json:"results"`
}

// RunOptions carries the injected clock (for determinism), tool version, scanned
// target, and the waiver/attestation register.
type RunOptions struct {
	Now         time.Time
	ToolVersion string
	Target      string
	Register    *AttestationRegister
}

// RunPacks evaluates the enabled frameworks' controls against an engine Report
// and returns per-control dispositions with evidence and crosswalk. It is a pure
// function of (catalog, report, options): the same inputs always produce the
// same report.
func RunPacks(cat *Catalog, frameworks []string, rep *engine.Report, opts RunOptions) *ComplianceReport {
	ran := map[string]bool{}
	for _, mr := range rep.ModuleRuns {
		ran[mr.Module] = true
	}
	ts := opts.Now.UTC().Format(time.RFC3339)
	tool := strings.TrimSpace("docker-security " + opts.ToolVersion)

	var results []ControlResult
	for _, fw := range frameworks {
		p := cat.Pack(fw)
		if p == nil {
			continue
		}
		for _, ctl := range p.Controls {
			res := ControlResult{
				Framework: fw, Version: p.Version, ID: ctl.ID, Title: ctl.Title,
				Assessment: ctl.Assessment, MapsTo: ctl.MapsTo, Remediation: ctl.Remediation,
			}
			res.Evidence = Evidence{Check: ctl.Check, Timestamp: ts, Tool: tool, Target: opts.Target}
			disposeControl(&res, ctl, rep, ran)
			applyRegister(&res, ctl, opts)
			results = append(results, res)
		}
	}
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Framework != results[j].Framework {
			return results[i].Framework < results[j].Framework
		}
		return lessControlID(results[i].ID, results[j].ID)
	})
	return &ComplianceReport{
		Target: opts.Target, GeneratedAt: ts, ToolVersion: opts.ToolVersion,
		Frameworks: append([]string(nil), frameworks...), Results: results,
	}
}

// disposeControl sets the raw disposition (before waivers/attestation) from the
// scan evidence.
func disposeControl(res *ControlResult, ctl PackControl, rep *engine.Report, ran map[string]bool) {
	switch ctl.Assessment {
	case "automated":
		disposeAutomated(res, ctl, rep, ran)
	case "hybrid":
		// A concrete violation still fails; otherwise it needs an attestation
		// (e.g. signature verification with no trust config is not a pass).
		if f, ok := firstViolation(ctl.Check, rep); ok {
			res.Disposition = DispFailed
			res.Evidence.Verdict = "FAIL"
			res.Evidence.Observed = f.Title
		} else {
			res.Disposition = DispManual
			res.Evidence.Verdict = "MANUAL"
			res.Evidence.Observed = "automated signal absent; requires attestation"
		}
	default: // manual | inherited | ""
		res.Disposition = DispManual
		res.Evidence.Verdict = "MANUAL"
		res.Evidence.Observed = fmt.Sprintf("%s control; requires recorded attestation", nonEmpty(ctl.Assessment, "manual"))
	}
}

func disposeAutomated(res *ControlResult, ctl PackControl, rep *engine.Report, ran map[string]bool) {
	matched := matchingFindings(ctl.Check, rep)
	moduleRan := ctl.Module == "" || ran[ctl.Module]

	if ctl.PresentMeans == "pass" {
		// The finding's presence is the evidence of satisfaction (e.g. an SBOM
		// was generated).
		switch {
		case len(matched) > 0:
			res.Disposition = DispSatisfied
			res.Evidence.Verdict = "PASS"
			res.Evidence.Observed = matched[0].Title
		case moduleRan:
			res.Disposition = DispFailed
			res.Evidence.Verdict = "FAIL"
			res.Evidence.Observed = "expected evidence (" + ctl.Check + ") not produced"
		default:
			res.Disposition = DispNotApplicable
			res.Evidence.Verdict = "N/A"
			res.Evidence.Observed = "module " + ctl.Module + " did not run for this target"
		}
		return
	}

	// Default polarity: a non-INFO matching finding is a violation.
	if f, ok := firstViolation(ctl.Check, rep); ok {
		res.Disposition = DispFailed
		res.Evidence.Verdict = "FAIL"
		res.Evidence.Observed = f.Title
	} else if moduleRan {
		res.Disposition = DispSatisfied
		res.Evidence.Verdict = "PASS"
		res.Evidence.Observed = "no violating " + ctl.Check + " finding"
	} else {
		res.Disposition = DispNotApplicable
		res.Evidence.Verdict = "N/A"
		res.Evidence.Observed = "module " + ctl.Module + " did not run for this target"
	}
}

// applyRegister upgrades a Failed control to Waived, or a Manual control to
// Satisfied, when a valid (unexpired) register entry exists.
func applyRegister(res *ControlResult, ctl PackControl, opts RunOptions) {
	if opts.Register == nil {
		return
	}
	switch res.Disposition {
	case DispFailed:
		if e, ok := opts.Register.Waiver(res.Framework, ctl.ID, opts.Now); ok {
			res.Disposition = DispWaived
			res.Evidence.Verdict = "WAIVED"
			res.Evidence.Observed = fmt.Sprintf("waived by %s until %s: %s", e.Owner, e.Expires.Format("2006-01-02"), e.Justification)
		}
	case DispManual:
		if e, ok := opts.Register.Attestation(res.Framework, ctl.ID, opts.Now); ok {
			res.Disposition = DispSatisfied
			res.Evidence.Verdict = "ATTESTED"
			res.Evidence.Observed = fmt.Sprintf("attested by %s: %s", e.Owner, e.Evidence)
		}
	}
}

// matchingFindings returns findings whose RuleID equals the check, or — when the
// check ends in "-" — begins with it (a rule family such as "DS-RAT-VULN-").
func matchingFindings(check string, rep *engine.Report) []engine.Finding {
	if check == "" {
		return nil
	}
	prefix := strings.HasSuffix(check, "-")
	var out []engine.Finding
	for _, f := range rep.Findings {
		if f.RuleID == check || (prefix && strings.HasPrefix(f.RuleID, check)) {
			out = append(out, f)
		}
	}
	return out
}

// firstViolation returns the first matching finding above INFO severity (an INFO
// finding, e.g. a scan summary, is not itself a control violation).
func firstViolation(check string, rep *engine.Report) (engine.Finding, bool) {
	for _, f := range matchingFindings(check, rep) {
		if f.Severity > engine.SeverityInfo {
			return f, true
		}
	}
	return engine.Finding{}, false
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// lessControlID orders dotted control ids numerically segment-by-segment so
// "2.6" sorts before "4.1" and "10.1" after "9.1".
func lessControlID(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aok := atoiSafe(as[i])
		bn, bok := atoiSafe(bs[i])
		if aok && bok {
			if an != bn {
				return an < bn
			}
			continue
		}
		if as[i] != bs[i] {
			return as[i] < bs[i]
		}
	}
	return len(as) < len(bs)
}

func atoiSafe(s string) (int, bool) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, s != ""
}
