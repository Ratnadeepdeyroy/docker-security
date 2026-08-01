package secrets

import (
	"context"
	"strings"
	"testing"
)

func TestGenerateHoneytokenDeterministic(t *testing.T) {
	a := GenerateHoneytoken("prod-image-2026")
	b := GenerateHoneytoken("prod-image-2026")
	if a != b {
		t.Errorf("same label yielded different honeytokens: %+v vs %+v", a, b)
	}
	if c := GenerateHoneytoken("other"); c.Value == a.Value {
		t.Error("different labels should yield different values")
	}
}

func TestGeneratedHoneytokenIsAWSShaped(t *testing.T) {
	h := GenerateHoneytoken("canary-1")
	if !strings.HasPrefix(h.Value, "AKIA") || len(h.Value) != 20 {
		t.Errorf("honeytoken %q is not AWS-access-key shaped", h.Value)
	}
	// It must trip the AWS access-key detector so it is *findable* once planted.
	s := New()
	if got := codeSet(s.ScanText(context.Background(), "c", []byte("k = "+h.Value), SourceFile)); got["DS-RAT-SEC-001"].Code == "" {
		t.Error("a generated honeytoken should match the AWS access-key detector")
	}
}

// TestHoneytokenReclassifiedNotLeaked: a planted canary is reported as a benign
// canary (DS-RAT-SEC-020, Info), not as a real AWS-key leak — but only when the
// scanner knows about it.
func TestHoneytokenReclassifiedNotLeaked(t *testing.T) {
	h := GenerateHoneytoken("deployed-here")
	content := []byte("aws_key = " + h.Value)

	// Without registration it reads as a real leak.
	plain := codeSet(New().ScanText(context.Background(), "c", content, SourceFile))
	if plain["DS-RAT-SEC-001"].Code == "" {
		t.Fatal("unregistered honeytoken should look like a real AWS key")
	}

	// With registration it is a benign canary at Info severity.
	s := New(WithHoneytokens(h))
	ds := s.ScanText(context.Background(), "c", content, SourceFile)
	if len(ds) != 1 {
		t.Fatalf("want exactly one detection, got %d", len(ds))
	}
	d := ds[0]
	if d.Code != "DS-RAT-SEC-020" || d.Kind != KindCanary {
		t.Errorf("canary not reclassified: code=%s kind=%s", d.Code, d.Kind)
	}
	if d.Severity.String() != "INFO" {
		t.Errorf("canary severity = %s, want INFO", d.Severity)
	}
}
