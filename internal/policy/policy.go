package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Policy document -------------------------------------------------------

// Effect is what a matched rule does to the decision.
type Effect string

const (
	// EffectDeny blocks in enforce mode (and would-block in audit mode).
	EffectDeny Effect = "deny"
	// EffectWarn surfaces a warning but never blocks.
	EffectWarn Effect = "warn"
	// EffectAllow is an explicit allowance: a matched allow rule exempts the
	// input from denial, expressing a carve-out ("allow this base image even
	// though a later rule would deny it").
	EffectAllow Effect = "allow"
)

func (e Effect) valid() bool {
	switch e {
	case EffectDeny, EffectWarn, EffectAllow:
		return true
	}
	return false
}

// Mode selects enforcement strength for the whole policy.
type Mode string

const (
	// ModeEnforce lets deny rules block. This is the default.
	ModeEnforce Mode = "enforce"
	// ModeAudit downgrades every would-be denial to a warning, so a new policy
	// can be rolled out and observed before it starts blocking deploys.
	ModeAudit Mode = "audit"
)

// Rule is one policy statement: when Match evaluates true, Effect applies.
type Rule struct {
	// ID is a stable, human-meaningful identifier, unique within the policy.
	ID string `json:"id"`
	// Description explains the intent for reviewers.
	Description string `json:"description,omitempty"`
	// Match is the boolean condition; the rule fires when it evaluates to true.
	Match string `json:"match"`
	// Effect is deny, warn, or allow.
	Effect Effect `json:"effect"`
	// Severity is the finding severity when this rule fires. Empty defaults from
	// the effect (deny -> HIGH, warn -> MEDIUM).
	Severity string `json:"severity,omitempty"`
	// Message is the human explanation attached to a firing.
	Message string `json:"message,omitempty"`
	// Remediation tells an operator (or an agent) how to become compliant.
	Remediation string `json:"remediation,omitempty"`
	// References are standards/citations (CIS, NIST, internal runbooks).
	References []string `json:"references,omitempty"`
}

// severity resolves the finding severity for a rule, applying the per-effect
// default when the author left it blank.
func (r Rule) severity() engine.Severity {
	if s := engine.ParseSeverity(r.Severity); s != engine.SeverityUnknown {
		return s
	}
	switch r.Effect {
	case EffectDeny:
		return engine.SeverityHigh
	case EffectWarn:
		return engine.SeverityMedium
	default:
		return engine.SeverityInfo
	}
}

// Policy is a versioned, reviewable set of rules plus governed waivers.
type Policy struct {
	// Version is the policy schema version. Only "1" is understood today; an
	// explicit version means a future engine can refuse or migrate old files.
	Version string `json:"version"`
	// Name identifies the policy in decisions and reports.
	Name string `json:"name"`
	// Description is a one-line human summary.
	Description string `json:"description,omitempty"`
	// Mode is enforce (default) or audit.
	Mode Mode `json:"mode,omitempty"`
	// Rules are evaluated in document order; order only affects report/explain
	// ordering, not the final decision (deny always wins over warn).
	Rules []Rule `json:"rules"`
	// Waivers are documented, expiring exceptions.
	Waivers []Waiver `json:"waivers,omitempty"`
}

// mode returns the effective mode, defaulting to enforce.
func (p *Policy) mode() Mode {
	if p.Mode == ModeAudit {
		return ModeAudit
	}
	return ModeEnforce
}

// Parse decodes a policy document from JSON without compiling it. Use Compile
// to get an evaluable engine (which also validates rule expressions).
func Parse(data []byte) (*Policy, error) {
	var p Policy
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields() // typo in a field name should fail loud, not be ignored
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	return &p, nil
}

// validate checks structural invariants that do not require expression parsing.
func (p *Policy) validate() error {
	if p.Version == "" {
		return fmt.Errorf("policy %q: version is required", p.Name)
	}
	if p.Version != "1" {
		return fmt.Errorf("policy %q: unsupported version %q (want \"1\")", p.Name, p.Version)
	}
	if p.Name == "" {
		return fmt.Errorf("policy: name is required")
	}
	if p.Mode != "" && p.Mode != ModeEnforce && p.Mode != ModeAudit {
		return fmt.Errorf("policy %q: unknown mode %q", p.Name, p.Mode)
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("policy %q: at least one rule is required", p.Name)
	}
	seen := map[string]bool{}
	for i, r := range p.Rules {
		if r.ID == "" {
			return fmt.Errorf("policy %q: rule %d: id is required", p.Name, i)
		}
		if seen[r.ID] {
			return fmt.Errorf("policy %q: duplicate rule id %q", p.Name, r.ID)
		}
		seen[r.ID] = true
		if strings.TrimSpace(r.Match) == "" {
			return fmt.Errorf("policy %q: rule %q: match is required", p.Name, r.ID)
		}
		if !r.Effect.valid() {
			return fmt.Errorf("policy %q: rule %q: invalid effect %q (want deny|warn|allow)", p.Name, r.ID, r.Effect)
		}
	}
	for i := range p.Waivers {
		if err := p.Waivers[i].validate(); err != nil {
			return fmt.Errorf("policy %q: %w", p.Name, err)
		}
	}
	return nil
}
