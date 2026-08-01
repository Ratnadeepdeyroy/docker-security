package policy

import (
	"testing"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

func TestWaiverSuppressesDenyUntilExpiry(t *testing.T) {
	p := &Policy{
		Version: "1", Name: "waived",
		Rules: []Rule{{ID: "cve-budget", Match: `severity_atleast("high") > 0`, Effect: EffectDeny}},
		Waivers: []Waiver{{
			RuleID:  "cve-budget",
			Reason:  "accepted for legacy image pending upgrade",
			Owner:   "secops@example.com",
			Expires: "2026-06-01T00:00:00Z",
		}},
	}
	eng, err := Compile(p)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	in := &Input{Findings: []engine.Finding{finding("DS-RAT-VULN-1", engine.SeverityHigh)}}

	// Before expiry: waived, so it does not block.
	before := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	res := eng.Evaluate(in, before)
	if res.Decision != DecisionAllow {
		t.Fatalf("before expiry: decision = %s, want allow", res.Decision)
	}
	if len(res.Denials()) != 0 {
		t.Fatalf("before expiry: expected no active denials, got %+v", res.Denials())
	}
	if fired := res.Firing(true); len(fired) != 1 || !fired[0].Waived {
		t.Fatalf("expected the rule recorded as waived, got %+v", fired)
	}

	// After expiry: the waiver lapses and the deny re-surfaces.
	after := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if res := eng.Evaluate(in, after); res.Decision != DecisionDeny {
		t.Fatalf("after expiry: decision = %s, want deny", res.Decision)
	}
}

func TestWaiverScopeNarrowsToImage(t *testing.T) {
	p := &Policy{
		Version: "1", Name: "scoped",
		Rules: []Rule{{ID: "cve-budget", Match: `severity_atleast("high") > 0`, Effect: EffectDeny}},
		Waivers: []Waiver{{
			RuleID:  "cve-budget",
			Reason:  "legacy only",
			Expires: "2026-12-01",
			Scope:   Scope{ImagePattern: `^legacy/`},
		}},
	}
	eng, err := Compile(p)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	f := []engine.Finding{finding("DS-RAT-VULN-1", engine.SeverityHigh)}

	inScope := &Input{Findings: f, Image: Image{Reference: "legacy/app:1"}}
	if res := eng.Evaluate(inScope, fixedNow); res.Decision != DecisionAllow {
		t.Fatalf("in-scope: decision = %s, want allow (waived)", res.Decision)
	}
	outScope := &Input{Findings: f, Image: Image{Reference: "prod/app:1"}}
	if res := eng.Evaluate(outScope, fixedNow); res.Decision != DecisionDeny {
		t.Fatalf("out-of-scope: decision = %s, want deny", res.Decision)
	}
}

func TestWaiverValidationRejectsBadWaivers(t *testing.T) {
	cases := map[string]Waiver{
		"no rule id":  {Reason: "x", Expires: "2026-12-01"},
		"no reason":   {RuleID: "r", Expires: "2026-12-01"},
		"no expiry":   {RuleID: "r", Reason: "x"},
		"bad expiry":  {RuleID: "r", Reason: "x", Expires: "not-a-date"},
		"bad pattern": {RuleID: "r", Reason: "x", Expires: "2026-12-01", Scope: Scope{ImagePattern: "("}},
	}
	for name, w := range cases {
		t.Run(name, func(t *testing.T) {
			if err := w.validate(); err == nil {
				t.Fatalf("expected validation error for %s", name)
			}
		})
	}
}

func TestWaiverExpiringWindow(t *testing.T) {
	ws := NewWaivers([]Waiver{
		{RuleID: "a", Reason: "x", Expires: "2026-01-10T00:00:00Z"},
		{RuleID: "b", Reason: "x", Expires: "2026-03-01T00:00:00Z"},
		{RuleID: "c", Reason: "x", Expires: "2025-12-01T00:00:00Z"}, // already expired
	})
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got := ws.Expiring(30*24*time.Hour, now)
	if len(got) != 1 || got[0].RuleID != "a" {
		t.Fatalf("expiring window = %+v, want only rule a", got)
	}
}
