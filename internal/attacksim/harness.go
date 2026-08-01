package attacksim

import (
	"context"
	"errors"
	"sort"
)

// This file runs scenarios against a ControlSet and reports which controls fired
// and, crucially, where a defense is MISSING (a gap). The run is safe by
// construction — it only calls Control.Evaluate on inert descriptors — but it is
// still gated behind an explicit authorization acknowledgement, because
// adversary emulation, even simulated, is something an operator must consciously
// opt into. Output ordering is deterministic (scenarios by ID) so results are
// stable and golden-testable.

// ErrNotAuthorized is returned when Run is called without an explicit opt-in.
// Adversary emulation must never run by accident.
var ErrNotAuthorized = errors.New("attacksim: run not authorized — set Options.Authorized and Options.Acknowledgement")

// ackPhrase is the exact acknowledgement an operator must provide, making the
// opt-in intentional rather than a stray boolean.
const ackPhrase = "I acknowledge this runs simulated, non-destructive attack scenarios"

// --- Options -------------------------------------------------------------

// Options gates and scopes a harness run. The zero value refuses to run (safe by
// default). Only include specifies a subset of scenario IDs; empty means all.
type Options struct {
	// Authorized must be true and Acknowledgement must equal AckPhrase() for a
	// run to proceed. Two independent signals, so neither a stray true nor a
	// copied string alone is enough.
	Authorized      bool
	Acknowledgement string
	// Only, when non-empty, restricts the run to these scenario IDs.
	Only []string
}

// AckPhrase returns the exact acknowledgement string a caller must supply. It is
// exported so CLIs and tests reference the single source of truth.
func AckPhrase() string { return ackPhrase }

func (o Options) authorized() bool {
	return o.Authorized && o.Acknowledgement == ackPhrase
}

// --- Results -------------------------------------------------------------

// ScenarioResult is the outcome of validating one scenario: the verdicts from
// every relevant control and whether the defense held (Fired) or a Gap exists.
type ScenarioResult struct {
	Scenario Scenario
	Verdicts []Verdict
	Fired    bool // at least one expected-kind control fired
	Gap      bool // no expected-kind control fired — a validation failure
}

// Report is the full validation run: per-scenario results plus quick counts.
type Report struct {
	Results   []ScenarioResult
	Total     int
	Validated int // scenarios where a control fired as expected
	Gaps      int // scenarios where no control fired (defenses did not hold)
}

// --- Run -----------------------------------------------------------------

// Run validates scenarios against the control set. It returns ErrNotAuthorized
// unless the caller has explicitly opted in. It never executes any scenario — it
// only evaluates each inert Event against the controls.
func Run(ctx context.Context, scenarios []Scenario, controls *ControlSet, opts Options) (*Report, error) {
	if !opts.authorized() {
		return nil, ErrNotAuthorized
	}
	if controls == nil {
		controls = NewControlSet()
	}
	selected := filterScenarios(scenarios, opts.Only)

	rep := &Report{Total: len(selected)}
	for _, sc := range selected {
		verdicts := controls.evaluate(ctx, sc.Event, sc.Expect)
		fired := false
		for _, v := range verdicts {
			if v.Fired {
				fired = true
				break
			}
		}
		res := ScenarioResult{Scenario: sc, Verdicts: verdicts, Fired: fired, Gap: !fired}
		if fired {
			rep.Validated++
		} else {
			rep.Gaps++
		}
		rep.Results = append(rep.Results, res)
	}
	// Deterministic order regardless of input ordering.
	sort.Slice(rep.Results, func(i, j int) bool { return rep.Results[i].Scenario.ID < rep.Results[j].Scenario.ID })
	return rep, nil
}

// filterScenarios returns only scenarios whose IDs are in only (all when empty),
// preserving determinism via a set lookup.
func filterScenarios(scenarios []Scenario, only []string) []Scenario {
	if len(only) == 0 {
		return scenarios
	}
	want := map[string]struct{}{}
	for _, id := range only {
		want[id] = struct{}{}
	}
	var out []Scenario
	for _, sc := range scenarios {
		if _, ok := want[sc.ID]; ok {
			out = append(out, sc)
		}
	}
	return out
}
