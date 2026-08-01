package runtime

import "github.com/Ratnadeepdeyroy/docker-security/internal/engine"

// This file implements response: what the sensor *does* when a rule fires.
// Detection without response is just noise, but automated response is dangerous
// — a false positive that kills a production pod is its own incident. So the
// design is safe-by-default and layered:
//
//   - Default mode is detect-only: every detection produces an alert Action and
//     nothing else. This is what ships enabled.
//   - Enforcement (kill / quarantine) is strictly opt-in AND double-gated: the
//     operator must select enforce mode *and* pass an explicit acknowledgement.
//     Without the acknowledgement, enforce silently degrades to alert — you
//     cannot accidentally arm destructive response.
//
// The decision (Plan) is a pure function of the detection and policy, so it is
// fully testable. The act of carrying out a destructive action against a live
// kernel/runtime is delegated to a Responder; the built-in one records intent
// (used by the daemon's alert path and by tests), and the real process-killing /
// network-isolating responder is a parked, platform-specific master action.

// ResponseMode selects the sensor's posture.
type ResponseMode string

const (
	// ResponseDetect alerts only. The safe default.
	ResponseDetect ResponseMode = "detect"
	// ResponseEnforce may take containment actions for severe detections, but
	// only when the policy is also acknowledged.
	ResponseEnforce ResponseMode = "enforce"
)

// ActionKind is the response taken for a detection.
type ActionKind string

const (
	ActionAlert      ActionKind = "alert"
	ActionKill       ActionKind = "kill"       // terminate the offending process
	ActionQuarantine ActionKind = "quarantine" // isolate the container (netns/pause)
)

// Action is a planned response for one detection.
type Action struct {
	Kind      ActionKind `json:"kind"`
	RuleID    string     `json:"rule_id"`
	Container string     `json:"container"`
	PID       int        `json:"pid,omitempty"`
	Reason    string     `json:"reason"`
}

// EnforceAck is the exact acknowledgement required to arm destructive response.
// Mirroring the attack-sim opt-in, a boolean alone is not enough — arming
// prevention must be a conscious, explicit act.
const EnforceAck = "I acknowledge dsecrat-runtime may kill or quarantine workloads on detection"

// ResponsePolicy decides the action for a detection. The zero value is
// detect-only (safe). KillSeverity is the minimum severity that triggers a
// destructive action in acknowledged enforce mode.
type ResponsePolicy struct {
	Mode         ResponseMode
	Acknowledged bool
	KillSeverity engine.Severity
}

// DefaultResponsePolicy returns the shipped posture: detect-only.
func DefaultResponsePolicy() ResponsePolicy {
	return ResponsePolicy{Mode: ResponseDetect, KillSeverity: engine.SeverityCritical}
}

// armed reports whether destructive response is actually permitted: enforce mode
// AND an explicit acknowledgement. This is the single guard both the planner and
// any responder consult.
func (p ResponsePolicy) armed() bool {
	return p.Mode == ResponseEnforce && p.Acknowledged
}

// Plan returns the response for a detection. In detect mode (or unacknowledged
// enforce) it is always an alert. In armed enforce mode, detections at or above
// KillSeverity are killed; container-escape and kernel-abuse additionally
// warrant quarantine because the blast radius is the host.
func (p ResponsePolicy) Plan(d Detection) Action {
	base := Action{RuleID: d.RuleID, Container: containerKey(d.Container), PID: d.Process.PID, Reason: d.Title}
	if !p.armed() || d.Severity < p.KillSeverity {
		base.Kind = ActionAlert
		return base
	}
	switch d.RuleID {
	case "DS-RAT-RT-003", "DS-RAT-RT-008": // escape / kernel abuse: contain the whole workload
		base.Kind = ActionQuarantine
	default:
		base.Kind = ActionKill
	}
	return base
}

// Responder carries out a planned Action. Implementations decide how (a live
// responder signals the kernel/runtime; the recording one just remembers).
type Responder interface {
	Do(a Action) error
}

// RecordingResponder captures the actions it is asked to perform without side
// effects. It backs the daemon's alert path and makes response testable without
// a live kernel. A real enforcing responder is a parked master action (NOTES.md).
type RecordingResponder struct {
	Actions []Action
}

// Do records the action. It never fails, so response bookkeeping cannot itself
// break the detection loop.
func (r *RecordingResponder) Do(a Action) error {
	r.Actions = append(r.Actions, a)
	return nil
}
