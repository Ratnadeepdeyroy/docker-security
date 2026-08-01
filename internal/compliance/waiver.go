package compliance

import (
	"fmt"
	"sort"
	"time"
)

// --- Waivers (documented, expiring, auditable exceptions) ------------------

// Waiver records an accepted risk: a specific control is knowingly suppressed
// until a date, with a justification and an owner. Waivers are the auditable
// escape hatch demanded by every serious compliance regime — an exception that
// expires and re-surfaces beats a check silently disabled in code forever.
type Waiver struct {
	// Control is the native control id to suppress (e.g. "2.13"). Matching is
	// exact; a benchmark code may be given to scope cross-benchmark files.
	Control string `json:"control"`
	// Benchmark optionally scopes the waiver to one benchmark code ("docker",
	// "k8s"). Empty applies to any benchmark carrying the control id.
	Benchmark string `json:"benchmark,omitempty"`
	// Reason is the mandatory human justification recorded in the audit trail.
	Reason string `json:"reason"`
	// Owner is who accepted the risk (for accountability).
	Owner string `json:"owner,omitempty"`
	// Expires is the date the waiver stops applying (RFC3339). A zero/empty
	// value is treated as already expired — waivers must have an end date.
	Expires string `json:"expires,omitempty"`
}

// expiryTime parses Expires; a missing/invalid value returns the zero time,
// which Apply treats as expired. Parsing is total: bad input never panics.
func (w Waiver) expiryTime() time.Time {
	if w.Expires == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, w.Expires); err == nil {
		return t
	}
	// Accept a bare date (YYYY-MM-DD) as end-of-day UTC for author convenience.
	if t, err := time.Parse("2006-01-02", w.Expires); err == nil {
		return t.Add(24*time.Hour - time.Second)
	}
	return time.Time{}
}

// active reports whether the waiver applies to the given benchmark at time now.
// The clock is injected (never time.Now here) so scans stay deterministic.
func (w Waiver) active(benchmarkCode string, now time.Time) bool {
	if w.Benchmark != "" && w.Benchmark != benchmarkCode {
		return false
	}
	exp := w.expiryTime()
	if exp.IsZero() {
		return false // no valid expiry ⇒ not honored
	}
	return now.Before(exp)
}

// Waivers is a set of waivers with an evaluation clock. Construct with the
// benchmark code you are scoring so Apply can honor per-benchmark scoping.
type Waivers struct {
	items []Waiver
}

// NewWaivers wraps a slice of waivers.
func NewWaivers(items []Waiver) *Waivers { return &Waivers{items: items} }

// Apply marks results as waived in place when a matching, unexpired waiver
// exists at time now. It returns the report for chaining. The original Status
// is preserved; only Waived/WaiverReason are set, so gating and scoring use the
// demoted status while the export still shows the true verdict.
func (ws *Waivers) Apply(rep *Report, benchmarkCode string, now time.Time) *Report {
	if ws == nil || len(ws.items) == 0 {
		return rep
	}
	for i := range rep.Results {
		res := &rep.Results[i]
		if res.Status != StatusFail && res.Status != StatusWarn {
			continue
		}
		for _, w := range ws.items {
			if w.Control != res.Control.ID {
				continue
			}
			if !w.active(benchmarkCode, now) {
				continue
			}
			res.Waived = true
			res.WaiverReason = fmt.Sprintf("%s (expires %s)", w.Reason, w.Expires)
			break
		}
	}
	return rep
}

// Expiring returns waivers that expire within the given window from now, sorted
// by expiry then control id. This drives a "these exceptions lapse soon" nudge
// so accepted risk is re-reviewed rather than forgotten.
func (ws *Waivers) Expiring(within time.Duration, now time.Time) []Waiver {
	if ws == nil {
		return nil
	}
	cutoff := now.Add(within)
	var out []Waiver
	for _, w := range ws.items {
		exp := w.expiryTime()
		if exp.IsZero() {
			continue
		}
		if !exp.Before(now) && exp.Before(cutoff) {
			out = append(out, w)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].expiryTime().Equal(out[j].expiryTime()) {
			return out[i].expiryTime().Before(out[j].expiryTime())
		}
		return compareControlID(out[i].Control, out[j].Control)
	})
	return out
}
