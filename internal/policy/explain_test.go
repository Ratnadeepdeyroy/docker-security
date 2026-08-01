package policy

import (
	"strings"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

func TestExplainDenialCarriesFactsAndRemediation(t *testing.T) {
	eng := mustCompile(t, ModeEnforce,
		Rule{
			ID:          "require-signature",
			Match:       `!signed`,
			Effect:      EffectDeny,
			Message:     "image is not signed by a trusted key",
			Remediation: "Sign the image: dsecrat sign --image <ref>",
		},
		Rule{
			ID:          "cve-budget",
			Match:       `severity_atleast("critical") > 0`,
			Effect:      EffectDeny,
			Message:     "image exceeds the critical-CVE budget",
			Remediation: "Rebuild on a patched base image to clear critical CVEs",
		},
	)
	in := &Input{
		Attest:   StaticAttestation{IsSigned: false},
		Findings: []engine.Finding{finding("DS-RAT-VULN-1", engine.SeverityCritical)},
	}
	res := eng.Evaluate(in, fixedNow)
	ex := eng.Explain(res, in)

	if ex.Decision != DecisionDeny {
		t.Fatalf("explain decision = %s, want deny", ex.Decision)
	}
	if len(ex.Denials) != 2 {
		t.Fatalf("denials = %d, want 2", len(ex.Denials))
	}
	// Every denial must expose the concrete facts that tripped it, so an agent
	// can act without guessing.
	var sigFacts map[string]string
	for _, d := range ex.Denials {
		if d.RuleID == "require-signature" {
			sigFacts = d.Facts
		}
	}
	if sigFacts["signed"] != "false" {
		t.Fatalf("expected fact signed=false, got %+v", sigFacts)
	}
	// Remediation is the de-duplicated union across denials — the agent's to-do.
	if len(ex.Remediation) != 2 {
		t.Fatalf("remediation = %+v, want 2 distinct steps", ex.Remediation)
	}
	if !strings.Contains(ex.Summary, "DENIED") {
		t.Fatalf("summary = %q, want a DENIED headline", ex.Summary)
	}
}

func TestExplainCollectsCountFacts(t *testing.T) {
	eng := mustCompile(t, ModeEnforce, Rule{
		ID:     "cve-budget",
		Match:  `severity_atleast("high") > 2`,
		Effect: EffectDeny,
	})
	in := &Input{Findings: []engine.Finding{
		finding("a", engine.SeverityCritical),
		finding("b", engine.SeverityHigh),
		finding("c", engine.SeverityHigh),
	}}
	ex := eng.Explain(eng.Evaluate(in, fixedNow), in)
	if len(ex.Denials) != 1 {
		t.Fatalf("denials = %d", len(ex.Denials))
	}
	// The fact key mirrors the source condition and carries the evaluated count.
	if got := ex.Denials[0].Facts[`severity_atleast("high")`]; got != "3" {
		t.Fatalf("severity_atleast fact = %q, want 3", got)
	}
}

func TestExplainAllowIsClean(t *testing.T) {
	eng := mustCompile(t, ModeEnforce, Rule{ID: "r", Match: `!signed`, Effect: EffectDeny})
	in := &Input{Attest: StaticAttestation{IsSigned: true}}
	ex := eng.Explain(eng.Evaluate(in, fixedNow), in)
	if ex.Decision != DecisionAllow || len(ex.Denials) != 0 {
		t.Fatalf("expected clean allow, got %s with %d denials", ex.Decision, len(ex.Denials))
	}
	if !strings.Contains(ex.Summary, "ALLOWED") {
		t.Fatalf("summary = %q", ex.Summary)
	}
}
