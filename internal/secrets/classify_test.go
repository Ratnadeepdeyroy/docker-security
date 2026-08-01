package secrets

import (
	"context"
	"testing"
)

// TestHeuristicClassifierJudgments exercises the classifier directly: it must
// reject the three big entropy-detector false positives and accept a genuine
// mixed-alphabet credential.
func TestHeuristicClassifierJudgments(t *testing.T) {
	c := HeuristicClassifier{}
	cases := []struct {
		name       string
		value      string
		wantSecret bool
	}{
		{"uuid", "550e8400-e29b-41d4-a716-446655440000", false},
		{"sha256-hex", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b1b6e5c1f3a2d4e6f8091a2b3", false},
		{"credential", "k7Jd9fLp2Qw8zXcV3bNm5tYr1sAe6uHi", true},
	}
	for _, tc := range cases {
		v := c.Classify(Candidate{Value: tc.value, Entropy: shannonEntropy(tc.value)})
		if v.IsSecret != tc.wantSecret {
			t.Errorf("%s: IsSecret = %v (label %q), want %v", tc.name, v.IsSecret, v.Label, tc.wantSecret)
		}
	}
}

// TestEntropySweepOffByDefault: a context-free high-entropy token is invisible
// to the default scanner (the classifier gates the sweep, and it is off).
func TestEntropySweepOffByDefault(t *testing.T) {
	content := "blob = k7Jd9fLp2Qw8zXcV3bNm5tYr1sAe6uHi" // key "blob" is not secret-named
	s := New()
	if ds := s.ScanText(context.Background(), "c", []byte(content), SourceFile); len(ds) != 0 {
		t.Errorf("entropy sweep should be off by default, got %d detections: %+v", len(ds), ds)
	}
}

// TestEntropySweepWithClassifier: enabling the classifier surfaces the bare
// token as DS-RAT-SEC-015 while still ignoring a UUID.
func TestEntropySweepWithClassifier(t *testing.T) {
	s := New(WithClassifier(HeuristicClassifier{}))

	found := s.ScanText(context.Background(), "c", []byte("blob = k7Jd9fLp2Qw8zXcV3bNm5tYr1sAe6uHi"), SourceFile)
	if got := codeSet(found); got["DS-RAT-SEC-015"].Code == "" {
		t.Errorf("classifier-enabled sweep should surface the bare token, got %v", keysOf(got))
	}

	// A UUID must still be ignored even with the sweep on.
	uuid := s.ScanText(context.Background(), "c", []byte("id = 550e8400-e29b-41d4-a716-446655440000"), SourceFile)
	if len(uuid) != 0 {
		t.Errorf("UUID must not be flagged even with classifier on, got %+v", uuid)
	}
}
