package policy

import "time"

// --- Decision model --------------------------------------------------------

// DecisionType is the aggregate verdict for an evaluation.
type DecisionType string

const (
	// DecisionAllow means nothing blocking or warning fired.
	DecisionAllow DecisionType = "allow"
	// DecisionWarn means a warn rule fired (or a deny fired under audit mode),
	// but nothing blocks.
	DecisionWarn DecisionType = "warn"
	// DecisionDeny means a deny rule fired in enforce mode and was not waived
	// or overridden by an explicit allow.
	DecisionDeny DecisionType = "deny"
)

// Blocks reports whether this decision should stop the workload/pipeline.
func (d DecisionType) Blocks() bool { return d == DecisionDeny }

// RuleResult records one rule's outcome for a specific evaluation.
type RuleResult struct {
	RuleID      string   `json:"rule_id"`
	Description string   `json:"description,omitempty"`
	Effect      Effect   `json:"effect"`
	Matched     bool     `json:"matched"`
	Message     string   `json:"message,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
	// Severity is the finding severity name for a matched deny/warn.
	Severity string `json:"severity,omitempty"`
	// Waived is set when a matching, unexpired waiver suppressed this firing.
	Waived bool `json:"waived,omitempty"`
	// WaiverReason carries the waiver's justification and expiry when waived.
	WaiverReason string `json:"waiver_reason,omitempty"`
	// Error, when set, is the evaluation error for this rule (fail-closed:
	// a rule that errors is treated as if it denied).
	Error string `json:"error,omitempty"`
}

// blocking reports whether a rule result contributes to a deny in enforce mode:
// a matched, unwaived deny, or a rule that errored (fail closed).
func (rr RuleResult) blocking() bool {
	if rr.Waived {
		return false
	}
	if rr.Error != "" {
		return true
	}
	return rr.Matched && rr.Effect == EffectDeny
}

// Result is the full outcome of evaluating a policy against one Input.
type Result struct {
	Policy   string       `json:"policy"`
	Mode     Mode         `json:"mode"`
	Decision DecisionType `json:"decision"`
	// Rules holds every rule's outcome in policy document order.
	Rules []RuleResult `json:"rules"`
	// EvaluatedAt is the injected evaluation time (for waiver expiry). It is
	// recorded so a decision is self-describing and auditable.
	EvaluatedAt time.Time `json:"evaluated_at"`
}

// Firing returns the rule results that matched (optionally including waived).
func (r *Result) Firing(includeWaived bool) []RuleResult {
	var out []RuleResult
	for _, rr := range r.Rules {
		if !rr.Matched && rr.Error == "" {
			continue
		}
		if rr.Waived && !includeWaived {
			continue
		}
		out = append(out, rr)
	}
	return out
}

// Denials returns the rule results that actually blocked admission. Because a
// block is a property of the aggregate decision (an allow override or audit mode
// can neutralize a would-be deny), this is empty unless Decision is deny — so a
// caller never emits a "violation" that contradicts an allow verdict.
func (r *Result) Denials() []RuleResult {
	if r.Decision != DecisionDeny {
		return nil
	}
	var out []RuleResult
	for _, rr := range r.Rules {
		if rr.blocking() {
			out = append(out, rr)
		}
	}
	return out
}

// Warnings returns rule results surfaced as warnings: matched warn rules, plus
// any rule that fired or errored but did not block (audit mode or an allow
// override). Waived firings are excluded.
func (r *Result) Warnings() []RuleResult {
	var out []RuleResult
	for _, rr := range r.Rules {
		if rr.Waived {
			continue
		}
		switch {
		case rr.Matched && rr.Effect == EffectWarn:
			out = append(out, rr)
		case rr.blocking() && r.Decision != DecisionDeny:
			out = append(out, rr)
		}
	}
	return out
}

// WaivedRules returns the firings that a matching waiver suppressed.
func (r *Result) WaivedRules() []RuleResult {
	var out []RuleResult
	for _, rr := range r.Rules {
		if rr.Waived {
			out = append(out, rr)
		}
	}
	return out
}
