package engine

import "time"

// ModuleRun records that a module executed, and any error it returned.
type ModuleRun struct {
	Module string `json:"module"`
	Error  string `json:"error,omitempty"`
}

// Report is the format-agnostic result of an analysis run. Formatters render
// it; frontends return it. It is safe to JSON-marshal directly.
type Report struct {
	Tool        string      `json:"tool"`
	TargetType  TargetType  `json:"target_type"`
	Target      string      `json:"target"`
	GeneratedAt time.Time   `json:"generated_at"`
	Findings    []Finding   `json:"findings"`
	ModuleRuns  []ModuleRun `json:"module_runs"`
}

// Add appends findings to the report.
func (r *Report) Add(f ...Finding) { r.Findings = append(r.Findings, f...) }

// Counts returns the number of findings at each severity.
func (r *Report) Counts() map[Severity]int {
	m := map[Severity]int{}
	for _, f := range r.Findings {
		m[f.Severity]++
	}
	return m
}

// Highest returns the most severe severity present, or SeverityUnknown if the
// report has no findings.
func (r *Report) Highest() Severity {
	h := SeverityUnknown
	for _, f := range r.Findings {
		if f.Severity > h {
			h = f.Severity
		}
	}
	return h
}

// FailsAt reports whether any finding meets or exceeds threshold. A threshold
// of SeverityUnknown never fails (gating disabled).
func (r *Report) FailsAt(threshold Severity) bool {
	if threshold == SeverityUnknown {
		return false
	}
	for _, f := range r.Findings {
		if f.Severity >= threshold {
			return true
		}
	}
	return false
}

// stamp is overridable in tests; production uses the wall clock.
var stamp = func() time.Time { return time.Now().UTC() }
