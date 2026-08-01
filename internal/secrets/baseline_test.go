package secrets

import (
	"context"
	"fmt"
	"testing"
)

// TestBaselineSuppressesAcceptedButNotNew is the whole point of a baseline:
// an accepted secret is silenced, a different one still fires.
func TestBaselineSuppressesAcceptedButNotNew(t *testing.T) {
	accepted := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	other := "ghp_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"

	fp := fingerprint(accepted)
	baselineJSON := fmt.Sprintf(`{
		"version": 1,
		"entries": [
			{"rule_id": "DS-RAT-SEC-004", "fingerprint": %q, "justification": "test fixture token, not real"}
		]
	}`, fp)

	b, err := ParseBaseline([]byte(baselineJSON))
	if err != nil {
		t.Fatalf("ParseBaseline: %v", err)
	}
	s := New(WithBaseline(b))

	// The accepted token is suppressed.
	content := "token: " + accepted
	if ds := s.ScanText(context.Background(), "c", []byte(content), SourceFile); len(ds) != 0 {
		t.Errorf("accepted token should be suppressed, got %d", len(ds))
	}
	// A different token of the same type still fires.
	content2 := "token: " + other
	if ds := s.ScanText(context.Background(), "c", []byte(content2), SourceFile); len(ds) != 1 {
		t.Errorf("a new token must still fire, got %d", len(ds))
	}
}

// TestLoadBaselineFromFile exercises the on-disk load path against a committed
// fixture, which also serves as documentation of the baseline file format.
func TestLoadBaselineFromFile(t *testing.T) {
	b, err := LoadBaseline("testdata/baseline.example.json")
	if err != nil {
		t.Fatalf("LoadBaseline: %v", err)
	}
	if b.Version != 1 || len(b.Entries) != 1 {
		t.Fatalf("unexpected baseline: %+v", b)
	}
	if b.Entries[0].Justification == "" {
		t.Error("baseline entry must carry a justification")
	}
	// The fixture accepts the golden GitHub token at app/config.yaml.
	token := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	s := New(WithBaseline(b))
	if ds := s.ScanText(context.Background(), "app/config.yaml", []byte("github_token: "+token), SourceFile); len(ds) != 0 {
		t.Errorf("committed baseline should suppress the fixture token, got %d", len(ds))
	}
}

func TestBaselinePathScoping(t *testing.T) {
	secret := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	fp := fingerprint(secret)
	// Accept only at path "allowed/config".
	baselineJSON := fmt.Sprintf(`{"version":1,"entries":[
		{"rule_id":"DS-RAT-SEC-004","fingerprint":%q,"path":"allowed/config","justification":"scoped"}
	]}`, fp)
	b, _ := ParseBaseline([]byte(baselineJSON))
	s := New(WithBaseline(b))

	if ds := s.ScanText(context.Background(), "allowed/config", []byte("t: "+secret), SourceFile); len(ds) != 0 {
		t.Errorf("scoped path should suppress, got %d", len(ds))
	}
	if ds := s.ScanText(context.Background(), "other/config", []byte("t: "+secret), SourceFile); len(ds) != 1 {
		t.Errorf("same secret at a different path must still fire, got %d", len(ds))
	}
}
