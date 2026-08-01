package policy

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// --- Compilation -----------------------------------------------------------
//
// Compiling a policy parses every rule's match expression into an AST and then
// statically validates it: unknown identifiers, unknown functions, wrong call
// arities, and malformed literal regexes are all caught here, before the policy
// is ever used at a gate. A policy that compiles is guaranteed to be free of
// these classes of error at evaluation time — the whole point of policy-as-code
// is that you find the bug in review, not in production.

// compiledRule pairs a rule with its parsed condition.
type compiledRule struct {
	rule Rule
	ast  node
}

// Engine is a compiled, ready-to-evaluate policy. It is immutable and safe for
// concurrent use: Evaluate reads only its rules and the per-call Input.
type Engine struct {
	policy  *Policy
	rules   []compiledRule
	waivers *Waivers
}

// Compile validates and compiles a policy into an Engine. It aggregates every
// rule error into one message so an author fixes all problems in a single pass
// rather than one recompile at a time.
func Compile(p *Policy) (*Engine, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	var (
		compiled []compiledRule
		errs     []string
	)
	for _, r := range p.Rules {
		ast, err := parseExpr(r.Match)
		if err != nil {
			errs = append(errs, fmt.Sprintf("rule %q: %v", r.ID, err))
			continue
		}
		if err := validateSemantics(ast); err != nil {
			errs = append(errs, fmt.Sprintf("rule %q: %v", r.ID, err))
			continue
		}
		compiled = append(compiled, compiledRule{rule: r, ast: ast})
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("policy %q failed to compile:\n  - %s", p.Name, strings.Join(errs, "\n  - "))
	}
	return &Engine{policy: p, rules: compiled, waivers: NewWaivers(p.Waivers)}, nil
}

// CompileBytes is a convenience that parses then compiles a JSON policy.
func CompileBytes(data []byte) (*Engine, error) {
	p, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return Compile(p)
}

// Policy returns the source policy document.
func (e *Engine) Policy() *Policy { return e.policy }

// validateSemantics walks an AST checking that every identifier and function is
// known and correctly used. Literal regex arguments are pre-compiled so a bad
// pattern fails at load time, not on the first finding that would match it.
func validateSemantics(root node) error {
	var check func(n node) error
	check = func(n node) error {
		switch t := n.(type) {
		case identNode:
			if _, ok := variables[t.name]; !ok {
				return fmt.Errorf("unknown identifier %q", t.name)
			}
		case callNode:
			b, ok := functions[t.name]
			if !ok {
				return fmt.Errorf("unknown function %q", t.name)
			}
			if len(t.args) != b.arity {
				return fmt.Errorf("function %q takes %d argument(s), got %d", t.name, b.arity, len(t.args))
			}
			if err := checkRegexpLiteral(t); err != nil {
				return err
			}
		}
		return n.walk(check)
	}
	return check(root)
}

// checkRegexpLiteral pre-validates a literal pattern passed to a regexp builtin.
func checkRegexpLiteral(c callNode) error {
	patIdx := -1
	switch c.name {
	case "resource_matches":
		patIdx = 0
	case "matches":
		patIdx = 1
	default:
		return nil
	}
	if patIdx >= len(c.args) {
		return nil
	}
	lit, ok := c.args[patIdx].(litNode)
	if !ok || lit.v.Kind != KindStr {
		return nil // non-literal pattern: validated at eval time
	}
	env := newEvalEnv(&Input{})
	_, err := env.compileRegexp(lit.v.s)
	return err
}

// --- Evaluation ------------------------------------------------------------

// Evaluate runs the compiled policy against an Input at time now (injected so
// waiver expiry is deterministic). It never returns an error: a rule that fails
// to evaluate is recorded on its RuleResult and treated as fail-closed, because
// a gate that crashed is a gate an attacker just walked through.
func (e *Engine) Evaluate(in *Input, now time.Time) *Result {
	env := newEvalEnv(in)
	res := &Result{
		Policy:      e.policy.Name,
		Mode:        e.policy.mode(),
		EvaluatedAt: now,
		Rules:       make([]RuleResult, 0, len(e.rules)),
	}

	for _, cr := range e.rules {
		rr := RuleResult{
			RuleID:      cr.rule.ID,
			Description: cr.rule.Description,
			Effect:      cr.rule.Effect,
			Remediation: cr.rule.Remediation,
			References:  cr.rule.References,
		}
		v, err := cr.ast.eval(env)
		if err != nil {
			rr.Error = err.Error()
			res.Rules = append(res.Rules, rr)
			continue
		}
		matched, err := v.AsBool()
		if err != nil {
			rr.Error = fmt.Sprintf("match expression must be boolean: %v", err)
			res.Rules = append(res.Rules, rr)
			continue
		}
		rr.Matched = matched
		if matched {
			rr.Message = cr.rule.Message
			rr.Severity = cr.rule.severity().String()
		}
		res.Rules = append(res.Rules, rr)
	}

	e.waivers.apply(res, in, now)
	res.Decision = decide(res)
	return res
}

// decide aggregates rule results into a single verdict. The ordering of
// precedence is the security-critical part, checked highest-risk first:
//
//   - A rule that errored means the policy could not be fully evaluated. That is
//     a broken gate: in enforce mode we fail closed (deny), and — crucially — an
//     explicit allow cannot rescue a policy we could not evaluate. In audit mode
//     it surfaces as a warning.
//   - Otherwise a matched, unwaived allow rule is an explicit carve-out and wins
//     over deny (the allowlist pattern: "images from our registry are fine").
//   - Otherwise an unwaived, matched deny blocks in enforce mode.
//   - Anything else that fired (a warn, or a would-be deny under audit) warns.
//   - Silence is allow.
func decide(res *Result) DecisionType {
	enforce := res.Mode != ModeAudit
	var hadError, deniedByRule, allowOverride, warned bool

	for _, rr := range res.Rules {
		if rr.Waived {
			continue
		}
		if rr.Error != "" {
			hadError = true
			continue
		}
		if !rr.Matched {
			continue
		}
		switch rr.Effect {
		case EffectDeny:
			deniedByRule = true
		case EffectAllow:
			allowOverride = true
		case EffectWarn:
			warned = true
		}
	}

	// A policy we could not evaluate fails closed before anything else.
	if hadError {
		if enforce {
			return DecisionDeny
		}
		return DecisionWarn
	}
	// An explicit allow carves out an exception (only over a cleanly-evaluated
	// policy, guaranteed by the error check above).
	if allowOverride {
		if warned {
			return DecisionWarn
		}
		return DecisionAllow
	}
	if enforce && deniedByRule {
		return DecisionDeny
	}
	if warned || deniedByRule { // deniedByRule here implies audit mode
		return DecisionWarn
	}
	return DecisionAllow
}

// ErrNotCompiled is returned by helpers that require a compiled engine.
var ErrNotCompiled = errors.New("policy: engine not compiled")
