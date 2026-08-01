// Package compliance is the shared machinery for hardening-benchmark auditing
// (CAPABILITY_SPEC domain 10). It is deliberately engine-agnostic at its core:
// benchmarks are *data* (a control catalogue with framework mappings), and the
// per-control pass/fail logic is injected by callers via an Assessor. That
// separation lets dockerbench and kubebench share one runner, one aggregation
// model, one waiver/drift/narrative layer, and one framework-mapping vocabulary
// while owning only their own evidence gathering and check functions.
//
// The engine only enters through finding.go, which projects a compliance.Report
// into the unified Finding stream. Everything else here has no engine import so
// it stays reusable and trivially testable.
package compliance

// --- Control severity levels (CIS "Level 1 / Level 2" profiles) ------------

// Level is the CIS benchmark profile a control belongs to. Level 1 is the
// baseline every environment should meet; Level 2 is defense-in-depth that can
// impose operational cost. Selecting a profile lets an auditor scope a run.
type Level int

const (
	// LevelUnset means the control declares no profile (treated as Level 1).
	LevelUnset Level = iota
	// Level1 is the recommended baseline (minimal operational impact).
	Level1
	// Level2 is stricter, higher-assurance hardening.
	Level2
)

func (l Level) String() string {
	switch l {
	case Level2:
		return "L2"
	case Level1, LevelUnset:
		return "L1"
	default:
		return "L?"
	}
}

// MarshalJSON renders levels as "L1"/"L2" so JSON exports read like a CIS
// profile column rather than an opaque integer.
func (l Level) MarshalJSON() ([]byte, error) { return []byte(`"` + l.String() + `"`), nil }

// --- Assessment status -----------------------------------------------------

// Status is the outcome of evaluating one control against collected evidence.
// It mirrors the PASS/WARN/FAIL/INFO vocabulary auditors expect from CIS tools.
type Status int

const (
	// StatusUnknown means the control was never evaluated (a programming error
	// if it reaches a report). It sorts first so it is easy to spot.
	StatusUnknown Status = iota
	// StatusInfo covers manual-review controls and inputs we could not read.
	// Per the contract, an unreadable input degrades to INFO, never a crash.
	StatusInfo
	// StatusPass means the control's requirement is satisfied.
	StatusPass
	// StatusWarn means partially satisfied or best-practice-but-not-required.
	StatusWarn
	// StatusFail means the requirement is violated.
	StatusFail
)

func (s Status) String() string {
	switch s {
	case StatusPass:
		return "PASS"
	case StatusWarn:
		return "WARN"
	case StatusFail:
		return "FAIL"
	case StatusInfo:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

// MarshalJSON renders statuses as their names so JSON exports read like an
// auditor's control sheet rather than opaque integers.
func (s Status) MarshalJSON() ([]byte, error) { return []byte(`"` + s.String() + `"`), nil }

// --- The control catalogue -------------------------------------------------

// Control is one benchmark requirement. A Benchmark is a catalogue of these,
// and framework mappings live on the control so a single scan can feed many
// audits (CIS + NIST + STIG + …) without hand-mapping downstream.
type Control struct {
	// ID is the native benchmark control number, e.g. "2.1" for CIS Docker.
	ID string `json:"id"`
	// Title is the one-line requirement, phrased as the desired end state.
	Title string `json:"title"`
	// Section groups controls for reporting, e.g. "Docker daemon configuration".
	Section string `json:"section,omitempty"`
	// Level is the CIS profile (Level 1 baseline vs Level 2 hardening).
	Level Level `json:"level"`
	// Scored is false for "manual"/informational controls that cannot be
	// auto-evaluated with confidence; those surface as INFO for human review.
	Scored bool `json:"scored"`
	// Description explains what the control protects against (the "why").
	Description string `json:"description,omitempty"`
	// Remediation is guided prose an operator can follow to fix a failure.
	Remediation string `json:"remediation,omitempty"`
	// Frameworks maps this control onto other compliance frameworks. Every
	// control MUST carry at least one non-CIS mapping (see benchmark tests).
	Frameworks []FrameworkRef `json:"frameworks,omitempty"`
	// Fix is an optional structured, agent-appliable remediation bundle. It is
	// advisory metadata only and never changes the deterministic scan result.
	Fix *Fix `json:"fix,omitempty"`
}

// Fix is a structured remediation an automation agent can propose or apply with
// a dry-run diff. It is intentionally declarative (what to set, where) rather
// than an executable script, so a human or agent reviews before acting.
type Fix struct {
	// Kind is the mechanism: "daemon.json", "file-perm", "sysctl",
	// "kubelet-flag", "apiserver-flag", "manifest". Consumers switch on it.
	Kind string `json:"kind"`
	// Target is the path or object the fix applies to (e.g. "/etc/docker/daemon.json").
	Target string `json:"target"`
	// Snippet is the concrete change (a JSON fragment, a flag, a mode string).
	Snippet string `json:"snippet"`
	// DryRun describes the effect in one line for a human-readable diff preview.
	DryRun string `json:"dry_run,omitempty"`
}

// Assessment is what an Assessor returns for a single control.
type Assessment struct {
	Status   Status
	Evidence string // human-readable: what we observed and why it passed/failed
	Actual   string // machine-readable observed value (empty when N/A)
}

// Assessor evaluates one control against already-collected evidence. Modules
// close over their evidence and dispatch by control ID. Assessors must be pure:
// same evidence in, same assessment out.
type Assessor func(c Control) Assessment

// Benchmark is a named, versioned control catalogue plus the profile it targets
// (e.g. self-managed vs a managed-Kubernetes variant). Controls are stored in
// the order the runner should evaluate and report them; Run re-sorts by control
// ID for a stable, human-sensible ordering regardless of source order.
type Benchmark struct {
	Code     string // short slug used in rule IDs, e.g. "docker", "k8s"
	Name     string // human title, e.g. "CIS Docker Benchmark"
	Version  string // benchmark version, e.g. "1.6.0"
	Profile  string // active profile, e.g. "self-managed", "eks"
	Controls []Control
}
