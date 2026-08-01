package compliance

import "sort"

// --- Result & Report -------------------------------------------------------

// Result pairs a control with the outcome of assessing it. The full Control is
// embedded (not just its id) so an exported report is self-describing evidence:
// an auditor reading the JSON sees the requirement, the mappings, the observed
// value, and the verdict together, with no external lookup.
type Result struct {
	Control  Control `json:"control"`
	Status   Status  `json:"status"`
	Evidence string  `json:"evidence,omitempty"`
	Actual   string  `json:"actual,omitempty"`
	// Waived is set when a matching, unexpired waiver suppressed a WARN/FAIL.
	// The original Status is preserved above; consumers gate on !Waived.
	Waived       bool   `json:"waived,omitempty"`
	WaiverReason string `json:"waiver_reason,omitempty"`
}

// effectiveStatus is the status used for scoring/gating: a live waiver demotes
// a WARN/FAIL to INFO so it neither fails a gate nor inflates the fail count,
// while the raw Status remains visible for the audit trail.
func (r Result) effectiveStatus() Status {
	if r.Waived && (r.Status == StatusFail || r.Status == StatusWarn) {
		return StatusInfo
	}
	return r.Status
}

// Report is the aggregated outcome of running a benchmark. It is safe to
// JSON-marshal directly as an auditor-ready, control-by-control evidence export.
type Report struct {
	Benchmark string   `json:"benchmark"`
	Version   string   `json:"version"`
	Profile   string   `json:"profile,omitempty"`
	Results   []Result `json:"results"`
}

// Run evaluates every control in the benchmark with the assessor and returns a
// deterministic report: results are sorted by control id with a human-aware
// numeric comparison, so re-running on identical evidence is byte-identical.
func (b Benchmark) Run(assess Assessor) *Report {
	rep := &Report{Benchmark: b.Name, Version: b.Version, Profile: b.Profile}
	for _, c := range b.Controls {
		a := assess(c)
		// A scored control that an assessor left Unknown is a coverage gap;
		// surface it as INFO rather than silently dropping it.
		if a.Status == StatusUnknown {
			a.Status = StatusInfo
			if a.Evidence == "" {
				a.Evidence = "no check implemented for this control; manual review required"
			}
		}
		rep.Results = append(rep.Results, Result{
			Control:  c,
			Status:   a.Status,
			Evidence: a.Evidence,
			Actual:   a.Actual,
		})
	}
	rep.sort()
	return rep
}

// sort orders results by control id (numeric-aware) for stable output.
func (r *Report) sort() {
	sort.SliceStable(r.Results, func(i, j int) bool {
		return compareControlID(r.Results[i].Control.ID, r.Results[j].Control.ID)
	})
}

// --- Aggregation -----------------------------------------------------------

// Counts tallies results by effective status (waivers demoted). The map always
// contains all five statuses so callers need not check for missing keys.
func (r *Report) Counts() map[Status]int {
	m := map[Status]int{StatusPass: 0, StatusWarn: 0, StatusFail: 0, StatusInfo: 0, StatusUnknown: 0}
	for _, res := range r.Results {
		m[res.effectiveStatus()]++
	}
	return m
}

// Score is the compliance pass rate over *scorable* results — those that landed
// on PASS or FAIL (effective). WARN and INFO are excluded from the denominator
// because they are advisory, not a hard pass/fail. Returns 0..100; a report
// with nothing scorable scores 100 (nothing failed).
func (r *Report) Score() int {
	pass, scorable := 0, 0
	for _, res := range r.Results {
		switch res.effectiveStatus() {
		case StatusPass:
			pass++
			scorable++
		case StatusFail:
			scorable++
		}
	}
	if scorable == 0 {
		return 100
	}
	return int(float64(pass) / float64(scorable) * 100.0)
}

// Failing returns the results that still count against the score (FAIL, not
// waived), in report order — the actionable worklist.
func (r *Report) Failing() []Result {
	var out []Result
	for _, res := range r.Results {
		if res.effectiveStatus() == StatusFail {
			out = append(out, res)
		}
	}
	return out
}

// FailsAt reports whether the report should fail a CI/CD gate: any effective
// FAIL fails; if warnAlso is set, effective WARN fails too. Waived controls
// never trip the gate.
func (r *Report) FailsAt(warnAlso bool) bool {
	for _, res := range r.Results {
		switch res.effectiveStatus() {
		case StatusFail:
			return true
		case StatusWarn:
			if warnAlso {
				return true
			}
		}
	}
	return false
}
