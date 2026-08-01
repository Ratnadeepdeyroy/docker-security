package compliance

import "sort"

// FrameworkCoverageStat summarizes how completely one framework is satisfied.
type FrameworkCoverageStat struct {
	Framework     string  `json:"framework"`
	Total         int     `json:"total"`
	Satisfied     int     `json:"satisfied"`
	Failed        int     `json:"failed"`
	Waived        int     `json:"waived"`
	NotApplicable int     `json:"not_applicable"`
	Manual        int     `json:"manual"` // unresolved manual (needs attestation)
	Unknown       int     `json:"unknown"`
	Resolved      int     `json:"resolved"` // any state but Unknown/unresolved-Manual
	CoveragePct   float64 `json:"coverage_pct"`
	AutomatedPct  float64 `json:"automated_pct"`
}

// Coverage aggregates a ComplianceReport into per-framework KPIs (COMPLIANCE_PLAN
// §5/§8): Coverage = resolved ÷ total; Automation rate = automatically-satisfied
// ÷ total. Frameworks are returned sorted for deterministic output.
func Coverage(rep *ComplianceReport) []FrameworkCoverageStat {
	byFw := map[string]*FrameworkCoverageStat{}
	order := []string{}
	for _, r := range rep.Results {
		s := byFw[r.Framework]
		if s == nil {
			s = &FrameworkCoverageStat{Framework: r.Framework}
			byFw[r.Framework] = s
			order = append(order, r.Framework)
		}
		s.Total++
		switch r.Disposition {
		case DispSatisfied:
			s.Satisfied++
			s.Resolved++
			if r.Assessment == "automated" {
				s.AutomatedPct++ // counted, converted to a ratio below
			}
		case DispFailed:
			s.Failed++
			s.Resolved++
		case DispWaived:
			s.Waived++
			s.Resolved++
		case DispNotApplicable:
			s.NotApplicable++
			s.Resolved++
		case DispManual:
			s.Manual++ // unresolved: awaiting attestation
		default:
			s.Unknown++
		}
	}
	out := make([]FrameworkCoverageStat, 0, len(order))
	for _, fw := range order {
		s := byFw[fw]
		if s.Total > 0 {
			s.CoveragePct = round1(100 * float64(s.Resolved) / float64(s.Total))
			s.AutomatedPct = round1(100 * s.AutomatedPct / float64(s.Total))
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Framework < out[j].Framework })
	return out
}

// Gaps returns the controls that are not fully resolved: Failed, unresolved
// Manual, or Unknown — the auditor's to-do list.
func Gaps(rep *ComplianceReport) []ControlResult {
	var out []ControlResult
	for _, r := range rep.Results {
		if r.Disposition == DispFailed || r.Disposition == DispManual || r.Disposition == DispUnknown {
			out = append(out, r)
		}
	}
	return out
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}
