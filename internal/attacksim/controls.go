package attacksim

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
)

// This file defines the seam between the attack-sim harness and the controls it
// validates. A Control is anything that can look at an inert Event and say
// whether it would fire. Phase 4 (admission) and Phase 5 (runtime detection)
// integrate by implementing this one method — the harness never imports their
// packages (see NOTES.md master actions). Two implementations ship now so the
// harness is usable and testable before those phases land: a reference
// PolicyControl that encodes the well-known bad properties, and a
// FixtureControl that replays recorded verdicts (the stub for a not-yet-built
// Phase 4/5).

// --- Control interface (the Phase 4/5 seam) ------------------------------

// Control is a defensive control the harness can probe. Implementations must be
// pure and deterministic over an Event: no wall clock, no randomness, no I/O.
type Control interface {
	// Name is a stable identifier for the control in reports.
	Name() string
	// Kind reports whether this is an admission or detection control.
	Kind() ControlKind
	// Evaluate returns the control's verdict for an inert event. It must never
	// execute the action — only reason about its descriptor.
	Evaluate(ctx context.Context, e Event) Verdict
}

// --- ControlSet ----------------------------------------------------------

// ControlSet is an ordered collection of controls. The harness asks the set,
// filtered by the kind a scenario expects, whether anything fires.
type ControlSet struct {
	controls []Control
}

// NewControlSet builds a set from the given controls, preserving order.
func NewControlSet(cs ...Control) *ControlSet { return &ControlSet{controls: cs} }

// Add appends a control (e.g. a real Phase 4 admission controller at wiring time).
func (s *ControlSet) Add(c Control) { s.controls = append(s.controls, c) }

// evaluate runs every control of the expected kind against an event and returns
// their verdicts in a deterministic order (by control name).
func (s *ControlSet) evaluate(ctx context.Context, e Event, expect ControlKind) []Verdict {
	var out []Verdict
	for _, c := range s.controls {
		if c.Kind() != expect {
			continue
		}
		out = append(out, c.Evaluate(ctx, e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Control < out[j].Control })
	return out
}

// --- Reference PolicyControl ---------------------------------------------
//
// A conservative, self-contained control that fires on the specific bad
// attributes our curated scenarios carry. It stands in for a real Phase 4/5
// control so the harness proves out end-to-end today; when the real controls
// land, they replace (or join) this one in the set.

// PolicyControl is a built-in reference control. matchers maps an attribute key
// to the value that should trip it; presence of the key with that value (or, for
// "*", any non-empty value) fires the control.
type PolicyControl struct {
	name     string
	kind     ControlKind
	matchers map[string]string
}

// ReferenceAdmissionControl returns a PolicyControl that denies the pod-shaped
// bad properties an admission webhook would reject.
func ReferenceAdmissionControl() *PolicyControl {
	return &PolicyControl{
		name: "reference-admission",
		kind: KindAdmission,
		matchers: map[string]string{
			"privileged":               "true",
			"hostPath":                 "*",
			"hostNetwork":              "true",
			"hostPID":                  "true",
			"allowPrivilegeEscalation": "true",
			"addedCapability":          "*",
			"mountsDockerSocket":       "true",
		},
	}
}

// ReferenceDetectionControl returns a PolicyControl that alerts on the runtime
// behaviors a detection engine would flag.
func ReferenceDetectionControl() *PolicyControl {
	return &PolicyControl{
		name: "reference-detection",
		kind: KindDetection,
		matchers: map[string]string{
			"execIntoContainer":       "true",
			"readServiceAccountToken": "true",
			"spawnsCryptominer":       "true",
			"reverseShell":            "true",
			"packageManagerExec":      "true",
		},
	}
}

func (p *PolicyControl) Name() string      { return p.name }
func (p *PolicyControl) Kind() ControlKind { return p.kind }

// Evaluate fires when the event carries any attribute the control matches on.
// It is deterministic and side-effect free; matched keys are reported sorted so
// the reason string is stable.
func (p *PolicyControl) Evaluate(_ context.Context, e Event) Verdict {
	var hits []string
	for k, want := range p.matchers {
		got := e.attr(k)
		if got == "" {
			continue
		}
		if want == "*" || got == want {
			hits = append(hits, k+"="+got)
		}
	}
	if len(hits) == 0 {
		return Verdict{Control: p.name, Kind: p.kind, Fired: false, Reason: "no matching policy signal"}
	}
	sort.Strings(hits)
	return Verdict{Control: p.name, Kind: p.kind, Fired: true, Reason: "matched " + join(hits)}
}

// --- FixtureControl (stub for a not-yet-built Phase 4/5) -----------------

// FixtureControl replays recorded verdicts keyed by ATT&CK technique. It is how
// tests pin "this control fires for T1611" without any real control present, and
// how a recorded baseline of a real control can be checked into testdata. A
// missing technique means the control did not fire (an honest gap).
type FixtureControl struct {
	name  string
	kind  ControlKind
	fires map[string]bool // technique -> fired
}

// NewFixtureControl builds a fixture control from a technique→fired map.
func NewFixtureControl(name string, kind ControlKind, fires map[string]bool) *FixtureControl {
	return &FixtureControl{name: name, kind: kind, fires: fires}
}

// LoadFixtureControl parses a recorded control from JSON of the form
// {"name":"...","kind":"admission","fires":{"T1611":true,...}}.
func LoadFixtureControl(data []byte) (*FixtureControl, error) {
	var raw struct {
		Name  string          `json:"name"`
		Kind  ControlKind     `json:"kind"`
		Fires map[string]bool `json:"fires"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse fixture control: %w", err)
	}
	if raw.Kind != KindAdmission && raw.Kind != KindDetection {
		return nil, fmt.Errorf("fixture control %q has invalid kind %q", raw.Name, raw.Kind)
	}
	return &FixtureControl{name: raw.Name, kind: raw.Kind, fires: raw.Fires}, nil
}

func (f *FixtureControl) Name() string      { return f.name }
func (f *FixtureControl) Kind() ControlKind { return f.kind }

// Evaluate looks up the event's technique in the recorded map.
func (f *FixtureControl) Evaluate(_ context.Context, e Event) Verdict {
	if f.fires[e.Technique] {
		return Verdict{Control: f.name, Kind: f.kind, Fired: true, Reason: "recorded fire for " + e.Technique}
	}
	return Verdict{Control: f.name, Kind: f.kind, Fired: false, Reason: "no recorded fire for " + e.Technique}
}

// join concatenates strings with ", " without pulling in strings.Join at call
// sites that already read cleaner this way.
func join(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}
