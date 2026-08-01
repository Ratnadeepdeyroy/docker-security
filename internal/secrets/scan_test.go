package secrets

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// codeSet indexes detections by rule code for convenient assertions.
func codeSet(ds []Detection) map[string]Detection {
	m := map[string]Detection{}
	for _, d := range ds {
		m[d.Code] = d
	}
	return m
}

func TestProviderRulesFire(t *testing.T) {
	// Each line carries one canonical, well-known *fake* credential shape.
	content := strings.Join([]string{
		`github_token: ghp_0123456789abcdefghijklmnopqrstuvwxyz`,
		`aws_access_key_id = AKIAIOSFODNN7EXAMPLE`,
		`aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
		`stripe = sk_live_0123456789ab` + `cdefghijklmn`,
		`db = postgres://admin:Tr0ub4dor3xyz@db.internal:5432/app`,
		`-----BEGIN RSA PRIVATE KEY-----`,
	}, "\n")

	s := New()
	got := codeSet(s.ScanText(context.Background(), "config", []byte(content), SourceFile))
	for _, want := range []string{
		"DS-RAT-SEC-001", // aws access key id
		"DS-RAT-SEC-002", // aws secret access key
		"DS-RAT-SEC-004", // github token
		"DS-RAT-SEC-007", // private key
		"DS-RAT-SEC-009", // stripe
		"DS-RAT-SEC-013", // db uri
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected rule %s to fire; got codes %v", want, keysOf(got))
		}
	}
	// The AWS secret key must land at Critical.
	if got["DS-RAT-SEC-002"].Severity.String() != "CRITICAL" {
		t.Errorf("DS-RAT-SEC-002 severity = %s, want CRITICAL", got["DS-RAT-SEC-002"].Severity)
	}
}

// TestValuesNeverStored is the core safety property: a Detection must not carry
// the raw secret anywhere in its fields.
func TestValuesNeverStored(t *testing.T) {
	secret := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	s := New()
	ds := s.ScanText(context.Background(), "config", []byte("token: "+secret), SourceFile)
	if len(ds) == 0 {
		t.Fatal("expected a detection")
	}
	for _, d := range ds {
		v := reflect.ValueOf(d)
		for i := 0; i < v.NumField(); i++ {
			if !v.Type().Field(i).IsExported() {
				continue
			}
			if f, ok := v.Field(i).Interface().(string); ok && strings.Contains(f, secret) {
				t.Fatalf("field %s leaked the secret value", v.Type().Field(i).Name)
			}
		}
		if d.Fingerprint == "" || d.Fingerprint == secret {
			t.Errorf("fingerprint not set/redacted: %q", d.Fingerprint)
		}
	}
}

// TestBenignContentIsQuiet is the false-positive guard: ordinary config, a
// UUID, and a git SHA must produce nothing on the default scanner.
func TestBenignContentIsQuiet(t *testing.T) {
	benign := strings.Join([]string{
		`name: my-service`,
		`port: 8080`,
		`enabled: true`,
		`request_id = "550e8400-e29b-41d4-a716-446655440000"`, // UUID
		`commit = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b`,   // sha1-ish hex
		`greeting = "hello world this is fine"`,
		`api_key = changeme`,      // placeholder
		`password = "${DB_PASS}"`, // env-var reference
	}, "\n")

	s := New()
	if ds := s.ScanText(context.Background(), "config", []byte(benign), SourceFile); len(ds) != 0 {
		t.Errorf("benign content produced %d detections, want 0: %+v", len(ds), ds)
	}
}

func TestDeterministicOrdering(t *testing.T) {
	content := "a: ghp_0123456789abcdefghijklmnopqrstuvwxyz\nb: AKIAIOSFODNN7EXAMPLE\n"
	s := New()
	a := s.ScanText(context.Background(), "c", []byte(content), SourceFile)
	b := s.ScanText(context.Background(), "c", []byte(content), SourceFile)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("repeated scan differs:\n%+v\n%+v", a, b)
	}
}

func TestOversizedFileSkipped(t *testing.T) {
	content := []byte("token: ghp_0123456789abcdefghijklmnopqrstuvwxyz")
	s := New(WithMaxFileBytes(4))
	if ds := s.ScanText(context.Background(), "c", content, SourceFile); len(ds) != 0 {
		t.Errorf("oversized file should be skipped, got %d detections", len(ds))
	}
}

// TestBinaryOnlyRunsAnchoredRules confirms binary blobs get only the anchored
// provider detectors, not the noisier generic ones.
func TestBinaryOnlyRunsAnchoredRules(t *testing.T) {
	s := New()
	// Anchored AWS key inside binary content: should still fire.
	bin := append([]byte{0x00, 0x01, 0x02}, []byte("AKIAIOSFODNN7EXAMPLE")...)
	if got := codeSet(s.ScanText(context.Background(), "bin", bin, SourceFile)); got["DS-RAT-SEC-001"].Code == "" {
		t.Error("anchored AWS key should fire even in binary content")
	}
	// A generic keyword assignment inside binary content: should NOT fire.
	bin2 := append([]byte{0x00}, []byte(`secret_key = k7Jd9fLp2Qw8zXcV3bNm5tYr1sAe6uHi`)...)
	if got := codeSet(s.ScanText(context.Background(), "bin", bin2, SourceFile)); got["DS-RAT-SEC-014"].Code != "" {
		t.Error("generic assignment must not run against binary content")
	}
}

func keysOf(m map[string]Detection) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
