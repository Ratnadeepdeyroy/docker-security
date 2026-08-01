package runtime

import "github.com/Ratnadeepdeyroy/docker-security/internal/engine"

// --- Rule contract -------------------------------------------------------

// Rule is one detection heuristic. It inspects a single event with access to
// accumulated State (process tree, image inventory, per-container history) and
// returns zero or more Detections.
//
// The contract that makes the whole engine deterministic and testable: Evaluate
// must be a pure function of (ev, st). It may read and update st, but it must
// never read the wall clock, a random source, or any ambient I/O. Everything a
// rule needs is in the event or the state built from prior events.
type Rule interface {
	// ID is the stable rule identifier (DS-RAT-RT-NNN).
	ID() string
	// Info returns the rule's static metadata (severity, ATT&CK, references).
	Info() RuleInfo
	// Evaluate returns detections for this event, or nil.
	Evaluate(ev *Event, st *State) []Detection
}

// ruleBase carries a rule's identity and static metadata and provides the
// boilerplate ID()/Info() plus a fire() helper that stamps a Detection from the
// triggering event. Concrete rules embed it and implement only Evaluate, so each
// rule file stays about detection logic, not plumbing.
type ruleBase struct {
	id   string
	info RuleInfo
}

func (b ruleBase) ID() string     { return b.id }
func (b ruleBase) Info() RuleInfo { return b.info }

// fire builds a Detection for this rule from the triggering event, copying the
// static metadata and snapshotting the actor. The triggering event is retained
// (redacted) for the forensic bundle. msg is the incident-time explanation.
func (b ruleBase) fire(ev *Event, msg string, meta map[string]string) Detection {
	// Snapshot the process with argv redacted so no secret ever rides along.
	proc := ev.Process
	proc.Args = redactArgs(ev.Process.Args)
	trigger := *ev
	trigger.Process = proc
	return Detection{
		RuleID:       b.id,
		Severity:     b.info.Severity,
		Title:        b.info.Title,
		Message:      msg,
		Technique:    b.info.Technique,
		Seq:          ev.Seq,
		TimeUnixNano: ev.TimeUnixNano,
		Container:    ev.Container,
		Process:      proc,
		Remediation:  b.info.Remediation,
		References:   b.info.References,
		Metadata:     meta,
		Trigger:      &trigger,
	}
}

// RuleInfo is a rule's static description. Keeping severity/technique/references
// out of Evaluate keeps detections consistent and lets `dsecrat-runtime rules`
// enumerate coverage without running anything.
type RuleInfo struct {
	Title       string
	Severity    engine.Severity
	Technique   Technique
	Remediation string
	References  []string
	// Description explains what the rule looks for and why it matters.
	Description string
	// Default reports whether the rule is on by default. Novel/behavioral rules
	// (agent-runtime, anomaly) ship off by default so correctness never depends
	// on them (SHARED_CONTRACT §4).
	Default bool
}

// --- Options -------------------------------------------------------------

// Options configures a Detector: which optional rule groups are enabled and how
// the response layer behaves. The zero value is a safe, detect-only sensor with
// only the deterministic signature rules active.
type Options struct {
	// EnableAnomaly turns on baseline deviation detection (DS-RAT-RT-050). Requires
	// a learned Baseline; off by default.
	EnableAnomaly bool
	// EnableAgentRuntime turns on the novel AI-agent-runtime rules (DS-RAT-RT-100).
	// Off by default — it is an intelligence layer on top of the core.
	EnableAgentRuntime bool
	// Baseline, when set, is the learned normal behavior used by the anomaly
	// rule and to suppress known-good activity.
	Baseline *Baseline
	// EgressAllow lists domains/CIDRs considered known-good egress; connections
	// outside it are candidate C2. Empty disables the allowlist check (the rule
	// then only fires on hard signals like IMDS/known-bad ports).
	EgressAllow []string
	// IntelFeed, when set, enables IOC matching (DS-RAT-RT-014). Nil = off, so
	// default detection stays deterministic and dependency-free.
	IntelFeed *IOCFeed
}

// --- Versioned rule set --------------------------------------------------

// RuleSet is an ordered, versioned collection of rules. Versioning matters
// operationally: an alert should record which rule pack produced it, so tuning
// changes are auditable.
type RuleSet struct {
	Version string
	rules   []Rule
}

// Rules returns the rules in stable order.
func (rs *RuleSet) Rules() []Rule { return rs.rules }

// defaultRules assembles every built-in rule. Optional rules are included but
// self-gate on Options inside their constructors/Evaluate, so the set is stable
// and enumerable while remaining off by default where required.
func defaultRules(opts Options) []Rule {
	return []Rule{
		newShellRule(),
		newDriftRule(),
		newEscapeRule(),
		newRuntimeBinaryRule(),
		newPrivEscRule(),
		newSensitiveFileRule(),
		newCredTheftRule(),
		newCryptoMiningRule(),
		newEgressRule(opts),
		newKernelAbuseRule(),
		newReverseShellRule(),
		newPersistenceRule(),
		newFilelessRule(),
		newIntelRule(opts),        // self-gates on opts.IntelFeed
		newAnomalyRule(opts),      // self-gates on opts.EnableAnomaly
		newAgentRuntimeRule(opts), // self-gates on opts.EnableAgentRuntime
	}
}

// NewRuleSet builds the built-in rule set for the given options.
func NewRuleSet(opts Options) *RuleSet {
	return &RuleSet{Version: RuleSetVersion, rules: defaultRules(opts)}
}
