package policy

import (
	"testing"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// fixedNow is an arbitrary but stable evaluation time for deterministic tests.
var fixedNow = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

// mustCompile builds an engine from rules, failing the test on error.
func mustCompile(t *testing.T, mode Mode, rules ...Rule) *Engine {
	t.Helper()
	eng, err := Compile(&Policy{Version: "1", Name: "test", Mode: mode, Rules: rules})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return eng
}

func finding(rule string, sev engine.Severity) engine.Finding {
	return engine.Finding{RuleID: rule, Module: "vuln", Severity: sev, Title: rule}
}

func TestEvaluateSeverityThresholdDenies(t *testing.T) {
	eng := mustCompile(t, ModeEnforce, Rule{
		ID:     "cve-budget",
		Match:  `severity_atleast("high") > 0`,
		Effect: EffectDeny,
	})
	in := &Input{Findings: []engine.Finding{finding("DS-RAT-VULN-1", engine.SeverityCritical)}}
	res := eng.Evaluate(in, fixedNow)
	if res.Decision != DecisionDeny {
		t.Fatalf("decision = %s, want deny", res.Decision)
	}
	if len(res.Denials()) != 1 || res.Denials()[0].RuleID != "cve-budget" {
		t.Fatalf("denials = %+v", res.Denials())
	}
}

func TestEvaluateCleanImageAllowed(t *testing.T) {
	eng := mustCompile(t, ModeEnforce, Rule{
		ID:     "cve-budget",
		Match:  `severity_atleast("critical") > 0`,
		Effect: EffectDeny,
	})
	in := &Input{Findings: []engine.Finding{finding("DS-RAT-VULN-1", engine.SeverityLow)}}
	if res := eng.Evaluate(in, fixedNow); res.Decision != DecisionAllow {
		t.Fatalf("decision = %s, want allow", res.Decision)
	}
}

func TestEvaluateUnsignedDenied(t *testing.T) {
	eng := mustCompile(t, ModeEnforce, Rule{
		ID:          "require-signature",
		Match:       `!signed`,
		Effect:      EffectDeny,
		Remediation: "Sign the image with a trusted key.",
	})
	// Unsigned -> deny.
	if res := eng.Evaluate(&Input{Attest: StaticAttestation{IsSigned: false}}, fixedNow); res.Decision != DecisionDeny {
		t.Fatalf("unsigned decision = %s, want deny", res.Decision)
	}
	// Signed -> allow.
	if res := eng.Evaluate(&Input{Attest: StaticAttestation{IsSigned: true}}, fixedNow); res.Decision != DecisionAllow {
		t.Fatalf("signed decision = %s, want allow", res.Decision)
	}
	// Nil attestation state must fail closed (treated as unsigned), never allow.
	if res := eng.Evaluate(&Input{}, fixedNow); res.Decision != DecisionDeny {
		t.Fatalf("nil-attest decision = %s, want deny (fail closed)", res.Decision)
	}
}

func TestEvaluateAuditModeDowngradesDenyToWarn(t *testing.T) {
	eng := mustCompile(t, ModeAudit, Rule{
		ID:     "cve-budget",
		Match:  `severity_atleast("high") > 0`,
		Effect: EffectDeny,
	})
	in := &Input{Findings: []engine.Finding{finding("DS-RAT-VULN-1", engine.SeverityHigh)}}
	res := eng.Evaluate(in, fixedNow)
	if res.Decision != DecisionWarn {
		t.Fatalf("audit decision = %s, want warn", res.Decision)
	}
	if res.Decision.Blocks() {
		t.Fatal("audit mode must never block")
	}
	if len(res.Warnings()) != 1 {
		t.Fatalf("warnings = %+v", res.Warnings())
	}
}

func TestEvaluateAllowOverridesDeny(t *testing.T) {
	eng := mustCompile(t, ModeEnforce,
		Rule{ID: "trusted-registry", Match: `registry == "internal.example.com"`, Effect: EffectAllow},
		Rule{ID: "no-critical", Match: `severity_atleast("critical") > 0`, Effect: EffectDeny},
	)
	// From the trusted registry, the deny is overridden.
	in := &Input{
		Image:    Image{Registry: "internal.example.com"},
		Findings: []engine.Finding{finding("DS-RAT-VULN-1", engine.SeverityCritical)},
	}
	if res := eng.Evaluate(in, fixedNow); res.Decision != DecisionAllow {
		t.Fatalf("trusted-registry decision = %s, want allow (override)", res.Decision)
	}
	// From an untrusted registry, the deny stands.
	in.Image.Registry = "docker.io"
	if res := eng.Evaluate(in, fixedNow); res.Decision != DecisionDeny {
		t.Fatalf("untrusted decision = %s, want deny", res.Decision)
	}
}

func TestEvaluateFailsClosedOnBadMatchType(t *testing.T) {
	// A match that evaluates to a number, not a bool, is a broken rule. In
	// enforce mode this must fail closed (deny), not be silently ignored.
	eng := mustCompile(t, ModeEnforce, Rule{ID: "broken", Match: `1 + 1`, Effect: EffectDeny})
	res := eng.Evaluate(&Input{}, fixedNow)
	if res.Decision != DecisionDeny {
		t.Fatalf("decision = %s, want deny (fail closed)", res.Decision)
	}
	if len(res.Rules) != 1 || res.Rules[0].Error == "" {
		t.Fatalf("expected a recorded rule error, got %+v", res.Rules)
	}
}

func TestEvaluateAllowCannotRescueBrokenPolicy(t *testing.T) {
	// Fail-closed must beat an explicit allow: if any rule could not be
	// evaluated, an allow rule cannot wave the workload through.
	eng := mustCompile(t, ModeEnforce,
		Rule{ID: "always-allow", Match: `true`, Effect: EffectAllow},
		Rule{ID: "broken", Match: `"x"`, Effect: EffectDeny},
	)
	if res := eng.Evaluate(&Input{}, fixedNow); res.Decision != DecisionDeny {
		t.Fatalf("decision = %s, want deny (broken policy fails closed)", res.Decision)
	}
}

func TestCompileErrors(t *testing.T) {
	cases := map[string]Rule{
		"unknown ident":    {ID: "r", Match: `signd`, Effect: EffectDeny},
		"unknown function": {ID: "r", Match: `severity_cont("high") > 0`, Effect: EffectDeny},
		"wrong arity":      {ID: "r", Match: `severity_count("high", "low") > 0`, Effect: EffectDeny},
		"bad regex":        {ID: "r", Match: `matches(registry, "(")`, Effect: EffectDeny},
		"syntax":           {ID: "r", Match: `severity_atleast("high" >`, Effect: EffectDeny},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Compile(&Policy{Version: "1", Name: "t", Rules: []Rule{r}}); err == nil {
				t.Fatalf("expected compile error for %s", name)
			}
		})
	}
}

func TestValidateRejectsBadDocuments(t *testing.T) {
	cases := map[string]*Policy{
		"no version":  {Name: "n", Rules: []Rule{{ID: "r", Match: "true", Effect: EffectDeny}}},
		"bad version": {Version: "2", Name: "n", Rules: []Rule{{ID: "r", Match: "true", Effect: EffectDeny}}},
		"no name":     {Version: "1", Rules: []Rule{{ID: "r", Match: "true", Effect: EffectDeny}}},
		"no rules":    {Version: "1", Name: "n"},
		"dup rule id": {Version: "1", Name: "n", Rules: []Rule{{ID: "r", Match: "true", Effect: EffectDeny}, {ID: "r", Match: "false", Effect: EffectWarn}}},
		"bad effect":  {Version: "1", Name: "n", Rules: []Rule{{ID: "r", Match: "true", Effect: "nuke"}}},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Compile(p); err == nil {
				t.Fatalf("expected validation error for %s", name)
			}
		})
	}
}

func TestDeterministicAcrossRuns(t *testing.T) {
	eng := mustCompile(t, ModeEnforce,
		Rule{ID: "a", Match: `severity_atleast("high") > 0`, Effect: EffectDeny},
		Rule{ID: "b", Match: `!signed`, Effect: EffectWarn},
	)
	in := &Input{
		Findings: []engine.Finding{finding("DS-RAT-VULN-1", engine.SeverityHigh)},
		Attest:   StaticAttestation{IsSigned: false},
	}
	first := eng.Evaluate(in, fixedNow)
	for i := 0; i < 50; i++ {
		got := eng.Evaluate(in, fixedNow)
		if got.Decision != first.Decision || len(got.Rules) != len(first.Rules) {
			t.Fatalf("run %d diverged: %s vs %s", i, got.Decision, first.Decision)
		}
	}
}
