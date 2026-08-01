package secrets

import (
	"context"
	"testing"
)

// These tests lock in the precision tuning that eliminated the false-positive
// flood observed scanning real images (private-key blocks embedded in shared
// libraries; `secretName = identifier` assignments throughout language runtimes).

func TestPrivateKeyNotFlaggedInBinary(t *testing.T) {
	s := New()
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD\n-----END RSA PRIVATE KEY-----\n"

	// A real key in a text file must fire.
	if got := codeSet(s.ScanText(context.Background(), "id_rsa", []byte(pem), SourceFile)); got["DS-RAT-SEC-007"].Code == "" {
		t.Errorf("private key in a text file should be detected")
	}
	// The same bytes embedded in a binary (a shared library shipping a test key)
	// must NOT fire — this was 80 false positives on rockylinux:9.
	binary := append([]byte{0x7f, 'E', 'L', 'F', 0x00, 0x01, 0x02, 0x00}, []byte(pem)...)
	binary = append(binary, 0x00, 0x00)
	if got := codeSet(s.ScanText(context.Background(), "usr/lib64/libgnutls.so.30", binary, SourceFile)); got["DS-RAT-SEC-007"].Code != "" {
		t.Errorf("private key inside a binary library must not be flagged (embedded test key)")
	}
}

func TestGenericAssignmentSourceVsConfig(t *testing.T) {
	s := New()
	ctx := context.Background()

	// Source code: a bare identifier RHS is a variable/call, not a secret.
	for _, code := range []string{
		"token = get_unstructured\n",
		"secret = self.credentials\n",
		"api_key = WRAPPER_ASSIGNMENTS\n",
		"password = default_factory\n",
	} {
		if ds := s.ScanText(ctx, "mod.py", []byte(code), SourceFile); len(ds) != 0 {
			t.Errorf("source identifier assignment must not fire: %q -> %d", code, len(ds))
		}
	}

	// Source code: a quoted high-entropy literal IS a hardcoded secret.
	if got := codeSet(s.ScanText(ctx, "app.py", []byte(`password = "hVn2Qz9Kx7Lm4Pw8Rt"`), SourceFile)); got["DS-RAT-SEC-014"].Code == "" {
		t.Errorf("quoted literal secret in source must be detected")
	}

	// Config file: an unquoted high-entropy value is a real credential.
	if got := codeSet(s.ScanText(ctx, "app.env", []byte("API_TOKEN=xY9zK2mN4pQ7rS1tU3vW"), SourceFile)); got["DS-RAT-SEC-014"].Code == "" {
		t.Errorf("unquoted secret in a config file must be detected")
	}
}

func TestPlausibleSecretValue(t *testing.T) {
	reject := []string{"get_unstructured", "WRAPPER_ASSIGNMENTS", "self", "default_factory", "header_value_parser"}
	keep := []string{"hVn2Qz9Kx7Lm", "aGVsbG8gd29ybGQ=", "AKIAIOSFODNN7EXAMPLE", "k7Jd9fLp2Qw8", "SuperSecretMixedCase"}
	for _, v := range reject {
		if plausibleSecretValue(v) {
			t.Errorf("%q should be rejected as a code identifier/word", v)
		}
	}
	for _, v := range keep {
		if !plausibleSecretValue(v) {
			t.Errorf("%q should be kept as a plausible credential", v)
		}
	}
}
