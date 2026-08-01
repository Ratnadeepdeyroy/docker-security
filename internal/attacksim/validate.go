package attacksim

import (
	"encoding/json"
	"sort"
)

// This file implements the phase's AI-age leap: continuous control-validation.
// A one-shot run tells you which defenses hold today; what actually protects you
// over time is noticing when a control that USED to fire goes silent. This pass
// compares a current run against a recorded baseline and surfaces regressions —
// a detection that stopped detecting is a security incident, not a passing test.
// It is OFF BY DEFAULT: it only does anything when a baseline is supplied.

// --- Baseline ------------------------------------------------------------

// Baseline records, per scenario ID, whether a control fired at a known-good
// point in time. It is deliberately tiny and JSON-serializable so it can be
// checked into a repo and diffed like any other artifact.
type Baseline struct {
	// Fired maps scenario ID -> did a control fire when this baseline was taken.
	Fired map[string]bool `json:"fired"`
}

// BaselineFrom builds a Baseline snapshot from a completed run, so today's green
// run becomes tomorrow's regression yardstick.
func BaselineFrom(rep *Report) Baseline {
	b := Baseline{Fired: map[string]bool{}}
	for _, r := range rep.Results {
		b.Fired[r.Scenario.ID] = r.Fired
	}
	return b
}

// LoadBaseline parses a Baseline from JSON.
func LoadBaseline(data []byte) (Baseline, error) {
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return Baseline{}, err
	}
	if b.Fired == nil {
		b.Fired = map[string]bool{}
	}
	return b, nil
}

// --- Regression detection ------------------------------------------------

// Regression is a scenario whose defense weakened relative to the baseline: it
// used to fire and now does not (the dangerous direction). Newly-firing controls
// are improvements, not regressions, and are not reported here.
type Regression struct {
	ScenarioID string
	Technique  string
	Name       string
	Severity   string
	WasFiring  bool
	NowFiring  bool
}

// CompareBaseline returns the regressions between a baseline and a current run,
// sorted by scenario ID. An empty result means every previously-working control
// still fires — the outcome you want from a scheduled validation agent.
func CompareBaseline(current *Report, baseline Baseline) []Regression {
	var out []Regression
	for _, r := range current.Results {
		was, known := baseline.Fired[r.Scenario.ID]
		if !known {
			continue // scenario not in baseline; nothing to regress against
		}
		if was && !r.Fired {
			out = append(out, Regression{
				ScenarioID: r.Scenario.ID,
				Technique:  r.Scenario.Technique,
				Name:       r.Scenario.Name,
				Severity:   r.Scenario.Severity,
				WasFiring:  was,
				NowFiring:  r.Fired,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ScenarioID < out[j].ScenarioID })
	return out
}
