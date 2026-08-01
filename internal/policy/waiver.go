package policy

import (
	"fmt"
	"regexp"
	"sort"
	"time"
)

// --- Waivers (governed, expiring exceptions) -------------------------------
//
// A waiver is how a team knowingly accepts a specific risk for a bounded time
// with a name attached to the decision. Three properties make it "governed"
// rather than a silent bypass: it names the exact rule it suppresses, it carries
// a mandatory human justification, and it expires. An exception that lapses and
// re-surfaces for review beats a check commented out in code forever — the
// waiver is the auditable escape hatch every serious policy regime requires.

// Waiver suppresses one rule's firing until it expires.
type Waiver struct {
	// RuleID is the rule to suppress. Matching is exact.
	RuleID string `json:"rule_id"`
	// Reason is the mandatory justification recorded in the audit trail.
	Reason string `json:"reason"`
	// Owner is who accepted the risk (for accountability).
	Owner string `json:"owner,omitempty"`
	// Expires is when the waiver stops applying (RFC3339, or a bare YYYY-MM-DD
	// treated as end-of-day UTC). A missing or unparseable value is treated as
	// already expired — a waiver must have an end date to be honored.
	Expires string `json:"expires"`
	// Scope optionally narrows the waiver to matching images.
	Scope Scope `json:"scope,omitempty"`
}

// Scope narrows a waiver to specific artifacts, so "we accept this CVE on the
// legacy image" does not silently excuse it everywhere.
type Scope struct {
	// ImagePattern is a regexp matched against the image reference. Empty = any.
	ImagePattern string `json:"image_pattern,omitempty"`
	// Registry is an exact registry host match. Empty = any.
	Registry string `json:"registry,omitempty"`
}

// validate checks a waiver is well-formed. It rejects the two footguns that
// make a waiver dangerous: no justification, and no (or invalid) expiry.
func (w Waiver) validate() error {
	if w.RuleID == "" {
		return fmt.Errorf("waiver: rule_id is required")
	}
	if w.Reason == "" {
		return fmt.Errorf("waiver for %q: reason (justification) is required", w.RuleID)
	}
	if w.expiryTime().IsZero() {
		return fmt.Errorf("waiver for %q: a valid expires date is required (RFC3339 or YYYY-MM-DD)", w.RuleID)
	}
	if w.Scope.ImagePattern != "" {
		if _, err := regexp.Compile(w.Scope.ImagePattern); err != nil {
			return fmt.Errorf("waiver for %q: invalid image_pattern: %w", w.RuleID, err)
		}
	}
	return nil
}

// expiryTime parses Expires; an empty/invalid value yields the zero time, which
// callers treat as expired. Parsing is total and never panics.
func (w Waiver) expiryTime() time.Time {
	if w.Expires == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, w.Expires); err == nil {
		return t
	}
	if t, err := time.Parse("2006-01-02", w.Expires); err == nil {
		return t.Add(24*time.Hour - time.Second)
	}
	return time.Time{}
}

// active reports whether the waiver is unexpired at now. A zero now means the
// caller did not inject an evaluation time; without a known clock we cannot
// judge expiry, so no waiver is honored — the safe default (an unknown time
// never silently keeps an exception alive).
func (w Waiver) active(now time.Time) bool {
	if now.IsZero() {
		return false
	}
	exp := w.expiryTime()
	return !exp.IsZero() && now.Before(exp)
}

// applies reports whether the waiver's scope covers the given input.
func (w Waiver) applies(in *Input) bool {
	if w.Scope.Registry != "" && w.Scope.Registry != in.Image.Registry {
		return false
	}
	if w.Scope.ImagePattern != "" {
		re, err := regexp.Compile(w.Scope.ImagePattern)
		if err != nil || !re.MatchString(in.Image.Reference) {
			return false
		}
	}
	return true
}

// Waivers is an ordered set of waivers.
type Waivers struct {
	items []Waiver
}

// NewWaivers wraps a slice of waivers.
func NewWaivers(items []Waiver) *Waivers { return &Waivers{items: items} }

// apply marks matching, in-scope, unexpired waivers on a Result's rule outcomes
// in place. Only firing deny/warn rules can be waived; a waiver never changes an
// allow or a non-matching rule. The clock is injected so waiver expiry is
// deterministic across runs.
func (ws *Waivers) apply(res *Result, in *Input, now time.Time) {
	if ws == nil || len(ws.items) == 0 {
		return
	}
	for i := range res.Rules {
		rr := &res.Rules[i]
		if !rr.Matched || (rr.Effect != EffectDeny && rr.Effect != EffectWarn) {
			continue
		}
		for _, w := range ws.items {
			if w.RuleID != rr.RuleID || !w.active(now) || !w.applies(in) {
				continue
			}
			rr.Waived = true
			rr.WaiverReason = fmt.Sprintf("%s (owner: %s, expires %s)", w.Reason, orNone(w.Owner), w.Expires)
			break
		}
	}
}

// Expiring returns waivers lapsing within the window from now, sorted by expiry
// then rule id. This drives a "these exceptions expire soon" nudge so accepted
// risk is re-reviewed rather than quietly forgotten.
func (ws *Waivers) Expiring(within time.Duration, now time.Time) []Waiver {
	if ws == nil {
		return nil
	}
	cutoff := now.Add(within)
	var out []Waiver
	for _, w := range ws.items {
		exp := w.expiryTime()
		if exp.IsZero() {
			continue
		}
		if !exp.Before(now) && exp.Before(cutoff) {
			out = append(out, w)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ei, ej := out[i].expiryTime(), out[j].expiryTime()
		if !ei.Equal(ej) {
			return ei.Before(ej)
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out
}

func orNone(s string) string {
	if s == "" {
		return "unspecified"
	}
	return s
}
