package runtime

import (
	"context"
	"errors"
	"io"
)

// --- Detector ------------------------------------------------------------

// Detector is the deterministic heart of the sensor: it feeds each event from a
// source through the rule set, threading accumulated State, and collects the
// resulting detections. It reads no clock and no randomness — identical input
// yields identical output — which is what makes it fully testable from recorded
// fixtures and safe to golden-test.
type Detector struct {
	rules *RuleSet
	state *State
	opts  Options
}

// NewDetector builds a detector for the given options and image inventory. The
// inventory seeds drift detection; pass nil when drift is not in scope.
func NewDetector(opts Options, images []ImageInventory) *Detector {
	st := newState(images)
	if opts.EnableAnomaly && opts.Baseline == nil {
		// Learning mode: no baseline supplied but anomaly requested → accumulate
		// one as we go (the profile/baseline generator uses this).
		st.baselineAcc = newBaselineAccumulator()
	}
	return &Detector{
		rules: NewRuleSet(opts),
		state: st,
		opts:  opts,
	}
}

// RuleSet exposes the active rule set (for enumeration and reporting).
func (d *Detector) RuleSet() *RuleSet { return d.rules }

// Process runs every rule against a single event and returns its detections.
// It updates state first so rules see a consistent process table. Order of
// detections follows rule order; callers that merge across events should
// SortDetections for a fully canonical order.
func (d *Detector) Process(ev *Event) []Detection {
	d.state.observe(ev)
	if d.state.baselineAcc != nil {
		d.state.baselineAcc.record(ev)
	}
	var out []Detection
	for _, r := range d.rules.Rules() {
		out = append(out, r.Evaluate(ev, d.state)...)
	}
	return out
}

// Run drains an EventSource, processing every event until the source reports
// io.EOF (bounded/replay) or ctx is cancelled (live). Detections are returned in
// canonical order. Errors other than io.EOF are surfaced with any detections
// gathered so far, so a truncated capture still yields partial results rather
// than nothing.
func (d *Detector) Run(ctx context.Context, src EventSource) ([]Detection, error) {
	var all []Detection
	for {
		ev, err := src.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			SortDetections(all)
			return all, err
		}
		all = append(all, d.Process(&ev)...)
	}
	SortDetections(all)
	return all, nil
}

// Baseline returns the behavior profile learned during a run, or nil if the
// detector was not learning. This is the raw material the profile generator
// turns into a least-privilege seccomp profile.
func (d *Detector) Baseline() *Baseline {
	if d.state.baselineAcc == nil {
		return nil
	}
	return d.state.baselineAcc.build()
}
