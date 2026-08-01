package verify

import (
	"context"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

func TestSupports(t *testing.T) {
	m := New()
	if !m.Supports(engine.TargetImage) || !m.Supports(engine.TargetRegistry) {
		t.Error("verify must support image and registry targets")
	}
	if m.Supports(engine.TargetDockerfile) || m.Supports(engine.TargetFilesystem) {
		t.Error("verify must not support dockerfile/filesystem targets")
	}
}

// TestNotConfiguredFailsSafe is the security-critical guard: with no trust
// config and no bundle, verification must NOT silently pass — it reports an
// INFO "not configured" finding and never a PASSED verdict.
func TestNotConfiguredFailsSafe(t *testing.T) {
	findings, err := New().Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetImage,
		Location: "example.com/img:1",
		Metadata: map[string]string{},
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected exactly one not-configured finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.RuleID != "DS-RAT-SUP-010" {
		t.Errorf("RuleID = %q, want DS-RAT-SUP-010 (not configured)", f.RuleID)
	}
	if f.Severity != engine.SeverityInfo {
		t.Errorf("severity = %s, want INFO", f.Severity)
	}
	// Must never claim verification passed when nothing was checked.
	if title := f.Title; title == "" || containsFold(title, "passed") {
		t.Errorf("not-configured finding must not read as a pass: %q", title)
	}
}

func TestBadConfigPathErrors(t *testing.T) {
	_, err := New().Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetImage,
		Location: "example.com/img:1",
		Metadata: map[string]string{"verify.trust": "/no/such/trust.json"},
	})
	if err == nil {
		t.Error("a missing trust-config path should surface an error, not be ignored")
	}
}

func containsFold(s, sub string) bool {
	return len(s) >= len(sub) && (indexFold(s, sub) >= 0)
}

func indexFold(s, sub string) int {
	lower := func(b byte) byte {
		if b >= 'A' && b <= 'Z' {
			return b + 32
		}
		return b
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		ok := true
		for j := 0; j < len(sub); j++ {
			if lower(s[i+j]) != lower(sub[j]) {
				ok = false
				break
			}
		}
		if ok {
			return i
		}
	}
	return -1
}
