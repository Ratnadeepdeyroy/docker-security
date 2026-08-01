package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// --- AI-age feature: explainable, agent-consumable decisions ---------------
//
// This is the phase's AI-age leap, and it is off by default: nothing in the
// deterministic decision path builds an Explanation, and callers only request
// one behind an explicit flag (`--explain`, or metadata policy.explain=true).
// The scan stays correct and reproducible with zero of this machinery running.
//
// The problem it solves: a bare "DENIED" is useless to an autonomous deployment
// agent. To close the loop without a human, the agent needs three things in a
// structured form — *what* decision was made, *why* (the exact predicate values
// that tripped each rule), and *what to change* to be admitted. Explanation
// carries all three as data, not prose, so an agent can act on it (sign the
// image, drop a capability, cut CVEs) and re-submit. It is generated from the
// same deterministic evaluation, so it never disagrees with the decision it
// explains, and it contains no model output — the "intelligence" is in the
// consumer, we just hand it clean, honest facts.

// Explanation is the structured, model-consumable account of a decision.
type Explanation struct {
	Policy   string            `json:"policy"`
	Decision DecisionType      `json:"decision"`
	Summary  string            `json:"summary"`
	Denials  []RuleExplanation `json:"denials,omitempty"`
	Warnings []RuleExplanation `json:"warnings,omitempty"`
	Waived   []RuleExplanation `json:"waived,omitempty"`
	// Remediation is the de-duplicated set of actions that, if taken, would
	// clear the current denials — the agent's to-do list to get admitted.
	Remediation []string  `json:"remediation,omitempty"`
	EvaluatedAt time.Time `json:"evaluated_at"`
}

// RuleExplanation explains one rule's firing, including the concrete input
// values that made it fire ("facts") so the reason is verifiable, not asserted.
type RuleExplanation struct {
	RuleID       string            `json:"rule_id"`
	Effect       Effect            `json:"effect"`
	Severity     string            `json:"severity,omitempty"`
	Reason       string            `json:"reason,omitempty"`
	Condition    string            `json:"condition"`
	Facts        map[string]string `json:"facts,omitempty"`
	Remediation  string            `json:"remediation,omitempty"`
	References   []string          `json:"references,omitempty"`
	Waived       bool              `json:"waived,omitempty"`
	WaiverReason string            `json:"waiver_reason,omitempty"`
}

// Explain renders a Result into an Explanation. It is a pure projection of the
// already-computed result plus the input (used to recover the predicate values),
// so calling it never changes a decision. It classifies rules through the same
// Denials/Warnings/WaivedRules accessors the CI gate and admission layer use, so
// an explanation can never disagree with the decision it explains.
func (e *Engine) Explain(res *Result, in *Input) *Explanation {
	byID := map[string]compiledRule{}
	for _, cr := range e.rules {
		byID[cr.rule.ID] = cr
	}
	env := newEvalEnv(in)

	explainRule := func(rr RuleResult) RuleExplanation {
		cr := byID[rr.RuleID]
		return RuleExplanation{
			RuleID:       rr.RuleID,
			Effect:       rr.Effect,
			Severity:     rr.Severity,
			Reason:       reasonOf(rr, cr.rule),
			Condition:    cr.rule.Match,
			Facts:        collectFacts(cr.ast, env),
			Remediation:  rr.Remediation,
			References:   rr.References,
			Waived:       rr.Waived,
			WaiverReason: rr.WaiverReason,
		}
	}

	ex := &Explanation{
		Policy:      res.Policy,
		Decision:    res.Decision,
		EvaluatedAt: res.EvaluatedAt,
	}
	remediation := map[string]bool{}

	for _, rr := range res.Denials() {
		ex.Denials = append(ex.Denials, explainRule(rr))
		if rr.Remediation != "" {
			remediation[rr.Remediation] = true
		}
	}
	for _, rr := range res.Warnings() {
		ex.Warnings = append(ex.Warnings, explainRule(rr))
	}
	for _, rr := range res.WaivedRules() {
		ex.Waived = append(ex.Waived, explainRule(rr))
	}

	for r := range remediation {
		ex.Remediation = append(ex.Remediation, r)
	}
	sort.Strings(ex.Remediation)
	ex.Summary = summarize(ex)
	return ex
}

// reasonOf picks the most informative human reason available for a firing.
func reasonOf(rr RuleResult, rule Rule) string {
	if rr.Error != "" {
		return "rule evaluation failed (fail-closed): " + rr.Error
	}
	if rule.Message != "" {
		return rule.Message
	}
	return rule.Description
}

// summarize produces the one-line human headline for the explanation.
func summarize(ex *Explanation) string {
	switch ex.Decision {
	case DecisionDeny:
		return fmt.Sprintf("DENIED by policy %q: %d rule(s) blocked admission", ex.Policy, len(ex.Denials))
	case DecisionWarn:
		return fmt.Sprintf("ALLOWED WITH WARNINGS by policy %q: %d warning(s)", ex.Policy, len(ex.Warnings))
	default:
		return fmt.Sprintf("ALLOWED by policy %q", ex.Policy)
	}
}

// collectFacts evaluates the leaf predicates of a rule's condition (its bare
// identifiers and function calls) and returns their concrete values. This is
// what turns "rule X fired" into "rule X fired because signed=false and
// severity_count(\"critical\")=3" — the difference between an agent guessing and
// an agent knowing.
func collectFacts(root node, env *evalEnv) map[string]string {
	facts := map[string]string{}
	var visit func(n node)
	visit = func(n node) {
		switch t := n.(type) {
		case identNode:
			facts[t.name] = evalToString(t, env)
			return
		case callNode:
			facts[factLabel(t)] = evalToString(t, env)
			// Still descend so a nested predicate argument is also surfaced.
		}
		_ = n.walk(func(c node) error { visit(c); return nil })
	}
	visit(root)
	if len(facts) == 0 {
		return nil
	}
	return facts
}

// evalToString evaluates a node for display, reporting errors inline rather than
// hiding them — a fact that could not be computed is itself worth showing.
func evalToString(n node, env *evalEnv) string {
	v, err := n.eval(env)
	if err != nil {
		return "error: " + err.Error()
	}
	return v.Display()
}

// factLabel renders a call node as "name(arg, arg)" using literal argument
// values where available, so the fact key reads like the source condition.
func factLabel(c callNode) string {
	parts := make([]string, len(c.args))
	for i, a := range c.args {
		if lit, ok := a.(litNode); ok {
			if lit.v.Kind == KindStr {
				parts[i] = `"` + lit.v.s + `"`
			} else {
				parts[i] = lit.v.Display()
			}
		} else {
			parts[i] = "…"
		}
	}
	return c.name + "(" + strings.Join(parts, ", ") + ")"
}
