// Package attacksim is a SAFE, offline adversary-emulation harness. It does not
// exploit anything: it carries a curated set of ATT&CK-for-Containers TTPs as
// inert, well-bounded *descriptors* and asks the security controls under test
// whether they would fire (deny at admission, or detect at runtime). It is
// control-VALIDATION, not an exploit kit — nothing here starts a process, opens
// a socket, writes outside a temp dir, or touches real infrastructure.
//
// The harness is deliberately decoupled from the controls it validates: Phase 4
// (admission) and Phase 5 (runtime detection) plug in by implementing the small
// Control interface (see controls.go). Until those phases exist, the package
// ships a reference PolicyControl and a fixture-backed control so scenarios can
// be validated end-to-end today. Everything is deterministic (scenarios sort by
// ID) and gated behind an explicit authorization acknowledgement.
package attacksim

// --- Control kinds -------------------------------------------------------

// ControlKind distinguishes the two defensive layers a scenario can exercise.
type ControlKind string

const (
	// KindAdmission is a preventive control that should deny a bad request
	// before it is admitted (Phase 4).
	KindAdmission ControlKind = "admission"
	// KindDetection is a runtime control that should raise an alert when a bad
	// action occurs (Phase 5).
	KindDetection ControlKind = "detection"
)

// --- Event: an inert TTP descriptor --------------------------------------

// Event describes, in data only, the adversary action a scenario represents. It
// is never executed. Attributes carry the specific bad properties (e.g.
// privileged=true, hostPath=/) that a control matches on — the same shape a real
// admission request or runtime event would expose, so a real Phase 4/5 control
// can evaluate it unchanged.
type Event struct {
	Technique  string            // ATT&CK technique id, e.g. "T1611"
	Tactic     string            // ATT&CK tactic name, e.g. "Privilege Escalation"
	Action     string            // short verb phrase, e.g. "create privileged pod"
	Target     string            // what it acts on, e.g. "pod/attacker"
	Attributes map[string]string // machine-matchable properties of the action
}

// attr is a nil-safe attribute lookup.
func (e Event) attr(k string) string {
	if e.Attributes == nil {
		return ""
	}
	return e.Attributes[k]
}

// --- Scenario ------------------------------------------------------------

// Scenario is one curated, safe adversary technique the harness can validate.
// Expect names which control layer *should* stop or catch it; Severity is how
// serious an undetected gap would be.
type Scenario struct {
	ID          string      // DS-RAT-ATK-NNN
	Technique   string      // ATT&CK technique id
	TacticName  string      // ATT&CK tactic
	Name        string      // short human name
	Description string      // what it does and why it matters
	Event       Event       // the inert action
	Expect      ControlKind // which control layer must fire
	Severity    string      // CRITICAL|HIGH|MEDIUM if the control fails to fire
	References  []string    // ATT&CK / hardening links
}

// --- Verdict -------------------------------------------------------------

// Verdict is a control's answer for one event: did it fire, which control, and
// why. A gap is simply the absence of any firing verdict where one was expected.
type Verdict struct {
	Control string
	Kind    ControlKind
	Fired   bool
	Reason  string
}
