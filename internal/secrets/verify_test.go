package secrets

import (
	"context"
	"strings"
	"testing"
)

// GitHub classic tokens are ghp_ + 36 chars; build exact-length fakes.
var (
	liveToken = "ghp_" + strings.Repeat("a", 32) + "live"
	deadToken = "ghp_" + strings.Repeat("b", 32) + "dead"
)

// TestVerificationOffByDefault: with no verifier, every finding is Skipped and
// no network call is possible.
func TestVerificationOffByDefault(t *testing.T) {
	s := New()
	ds := s.ScanText(context.Background(), "c", []byte("t: ghp_0123456789abcdefghijklmnopqrstuvwxyz"), SourceFile)
	if len(ds) != 1 || ds[0].Verify != VerifySkipped {
		t.Fatalf("default verify state = %v, want skipped", ds)
	}
}

// TestMockVerifierActiveVsInactive uses an injected mock (never the network) to
// confirm the active/inactive/critical-escalation wiring.
func TestMockVerifierActiveVsInactive(t *testing.T) {
	// The mock declares a token "active" iff it ends in "live".
	mock := VerifierFunc(func(_ context.Context, slug, secret string) VerifyState {
		if slug != "github-token" {
			return VerifyUnknown
		}
		if secret == liveToken {
			return VerifyActive
		}
		return VerifyInactive
	})
	s := New(WithVerifier(mock))

	live := s.ScanText(context.Background(), "c", []byte("t: "+liveToken), SourceFile)
	if len(live) != 1 || live[0].Verify != VerifyActive {
		t.Fatalf("live token verify = %v, want active", live)
	}
	// A confirmed-live key is escalated to Critical for triage.
	if live[0].Severity.String() != "CRITICAL" {
		t.Errorf("verified-live severity = %s, want CRITICAL", live[0].Severity)
	}

	dead := s.ScanText(context.Background(), "c", []byte("t: "+deadToken), SourceFile)
	if len(dead) != 1 || dead[0].Verify != VerifyInactive {
		t.Fatalf("dead token verify = %v, want inactive", dead)
	}
}

// TestVerifierReceivesNoValueForGenericFindings: generic findings have no
// verifier key, so the verifier is never called for them.
func TestVerifierNotCalledWithoutKey(t *testing.T) {
	called := false
	mock := VerifierFunc(func(_ context.Context, _, _ string) VerifyState {
		called = true
		return VerifyActive
	})
	s := New(WithVerifier(mock))
	// A generic assignment finding (DS-RAT-SEC-014) carries no verifier key.
	s.ScanText(context.Background(), "c", []byte(`secret_key = k7Jd9fLp2Qw8zXcV3bNm5tYr1sAe6uHi`), SourceFile)
	if called {
		t.Error("verifier must not be called for findings without a verifier key")
	}
}
