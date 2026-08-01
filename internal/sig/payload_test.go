package sig

import "testing"

const testDigest = "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"

func TestImagePayloadRoundTrip(t *testing.T) {
	data, err := NewImagePayload("registry.example.com/app:1.0", testDigest, map[string]string{"build": "42"})
	if err != nil {
		t.Fatalf("NewImagePayload: %v", err)
	}
	p, err := ParseImagePayload(data)
	if err != nil {
		t.Fatalf("ParseImagePayload: %v", err)
	}
	if p.SignedDigest() != testDigest {
		t.Errorf("SignedDigest = %q, want %q", p.SignedDigest(), testDigest)
	}
	if p.Critical.Type != criticalTypeImageSig {
		t.Errorf("critical type = %q", p.Critical.Type)
	}
	if p.Optional["build"] != "42" {
		t.Errorf("optional lost: %v", p.Optional)
	}
}

// TestImagePayloadRejectsBadDigest: a signature over a malformed/empty digest
// authenticates nothing, so construction must fail closed.
func TestImagePayloadRejectsBadDigest(t *testing.T) {
	bad := []string{
		"",
		"sha256:",
		"deadbeef",
		"md5:5891b5b522d5df086d0ff0b110fbd9d2",
		"sha256:XYZ1b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
		"sha256:5891b5b5", // too short
	}
	for _, d := range bad {
		if _, err := NewImagePayload("ref", d, nil); err == nil {
			t.Errorf("accepted malformed digest %q", d)
		}
	}
}

// TestImagePayloadDeterministic: identical inputs yield byte-identical payloads,
// which is what lets the ed25519 signature over them be reproducible.
func TestImagePayloadDeterministic(t *testing.T) {
	a, _ := NewImagePayload("ref", testDigest, map[string]string{"k": "v"})
	b, _ := NewImagePayload("ref", testDigest, map[string]string{"k": "v"})
	if string(a) != string(b) {
		t.Fatalf("payload not deterministic:\n%s\n%s", a, b)
	}
}
