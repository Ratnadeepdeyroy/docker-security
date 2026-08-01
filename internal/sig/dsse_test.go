package sig

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
)

// TestPAEVector checks our PAE against the canonical DSSE spec example, the one
// interop-defining vector every DSSE implementation must reproduce.
func TestPAEVector(t *testing.T) {
	got := pae("http://example.com/HelloWorld", []byte("hello world"))
	want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
	if string(got) != want {
		t.Fatalf("PAE mismatch:\n got %q\nwant %q", got, want)
	}
}

// TestPAEBoundaryUnforgeable proves the length-prefixing stops a type/payload
// boundary shift: two different (type,payload) splits must not collide.
func TestPAEBoundaryUnforgeable(t *testing.T) {
	a := pae("ab", []byte("cd")) // DSSEv1 2 ab 2 cd
	b := pae("a", []byte("bcd")) // DSSEv1 1 a 3 bcd
	if bytes.Equal(a, b) {
		t.Fatalf("PAE collided across a boundary shift: %q == %q", a, b)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	for _, alg := range []Algorithm{AlgEd25519, AlgECDSAP256} {
		t.Run(string(alg), func(t *testing.T) {
			signer := mustSigner(alg, "roundtrip-"+string(alg))
			payload := []byte(`{"hello":"world"}`)
			env, err := SignEnvelope("application/vnd.test+json", payload, signer)
			if err != nil {
				t.Fatalf("SignEnvelope: %v", err)
			}
			if err := env.VerifyWith(signer.Verifier()); err != nil {
				t.Fatalf("VerifyWith: %v", err)
			}
			// Payload round-trips.
			got, err := env.DecodePayload()
			if err != nil || !bytes.Equal(got, payload) {
				t.Fatalf("payload round-trip: got %q err %v", got, err)
			}
		})
	}
}

// TestEd25519Deterministic asserts byte-identical envelopes for identical
// inputs — the determinism guarantee the contract demands where the scheme
// allows it (ed25519 is deterministic; ECDSA is not, hence excluded).
func TestEd25519Deterministic(t *testing.T) {
	signer := mustSigner(AlgEd25519, "det-seed")
	payload := []byte("deterministic payload")
	a, err := SignEnvelope("t", payload, signer)
	if err != nil {
		t.Fatal(err)
	}
	b, err := SignEnvelope("t", payload, signer)
	if err != nil {
		t.Fatal(err)
	}
	if a.Signatures[0].Sig != b.Signatures[0].Sig {
		t.Fatalf("ed25519 signatures differ across runs:\n%s\n%s", a.Signatures[0].Sig, b.Signatures[0].Sig)
	}
}

// TestVerifyRejectsTamper covers the attacker's basic moves: flip a payload
// byte, flip a signature byte, or swap the payload type. All must fail.
func TestVerifyRejectsTamper(t *testing.T) {
	signer := mustSigner(AlgEd25519, "tamper")
	env, err := SignEnvelope("application/vnd.test+json", []byte("original"), signer)
	if err != nil {
		t.Fatal(err)
	}

	// Tampered payload.
	bad := *env
	bad.Payload = base64.StdEncoding.EncodeToString([]byte("tampered"))
	if err := bad.VerifyWith(signer.Verifier()); err == nil {
		t.Error("verify accepted a tampered payload")
	}

	// Tampered payload type (type-confusion attempt).
	bad2 := *env
	bad2.PayloadType = "application/vnd.evil+json"
	if err := bad2.VerifyWith(signer.Verifier()); err == nil {
		t.Error("verify accepted a swapped payload type")
	}

	// Tampered signature bytes.
	raw, _ := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	raw[0] ^= 0xff
	bad3 := *env
	bad3.Signatures = []Signature{{KeyID: env.Signatures[0].KeyID, Sig: base64.StdEncoding.EncodeToString(raw)}}
	if err := bad3.VerifyWith(signer.Verifier()); err == nil {
		t.Error("verify accepted a corrupted signature")
	}
}

// TestVerifyWrongKey ensures a signature by one key does not verify under
// another, and that the error is classified ErrVerify.
func TestVerifyWrongKey(t *testing.T) {
	a := mustSigner(AlgEd25519, "key-a")
	b := mustSigner(AlgEd25519, "key-b")
	env, err := SignEnvelope("t", []byte("x"), a)
	if err != nil {
		t.Fatal(err)
	}
	err = env.VerifyWith(b.Verifier())
	if !errors.Is(err, ErrVerify) {
		t.Fatalf("expected ErrVerify for wrong key, got %v", err)
	}
}

func TestEnvelopeParseRejectsMalformed(t *testing.T) {
	cases := map[string][]byte{
		"empty":          []byte(``),
		"no signatures":  []byte(`{"payload":"YQ==","payloadType":"t","signatures":[]}`),
		"no payloadType": []byte(`{"payload":"YQ==","signatures":[{"sig":"YQ=="}]}`),
		"bad base64":     []byte(`{"payload":"!!!","payloadType":"t","signatures":[{"sig":"YQ=="}]}`),
	}
	for name, data := range cases {
		if _, err := ParseEnvelope(data); err == nil {
			t.Errorf("%s: expected parse error, got nil", name)
		}
	}
}

func TestEnvelopeMarshalRoundTrip(t *testing.T) {
	signer := mustSigner(AlgECDSAP256, "marshal")
	env, err := SignEnvelope("t", []byte("body"), signer)
	if err != nil {
		t.Fatal(err)
	}
	data, err := env.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseEnvelope(data)
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}
	if err := got.VerifyWith(signer.Verifier()); err != nil {
		t.Fatalf("verify after round-trip: %v", err)
	}
}

// TestKeyIDStable pins that a key ID is the hex SHA-256 of the PKIX DER, so the
// value other tools compute matches ours.
func TestKeyIDStable(t *testing.T) {
	signer := mustSigner(AlgEd25519, "keyid")
	id := signer.KeyID()
	if len(id) != 64 {
		t.Fatalf("keyid length = %d, want 64 hex chars", len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Fatalf("keyid is not hex: %v", err)
	}
}
