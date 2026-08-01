package sig

import (
	"bytes"
	"testing"
)

func TestPEMRoundTrip(t *testing.T) {
	for _, alg := range []Algorithm{AlgEd25519, AlgECDSAP256} {
		t.Run(string(alg), func(t *testing.T) {
			signer := mustSigner(alg, "pem-"+string(alg))

			privPEM, err := MarshalPrivateKeyPEM(signer)
			if err != nil {
				t.Fatalf("MarshalPrivateKeyPEM: %v", err)
			}
			pubPEM, err := MarshalPublicKeyPEM(signer.Verifier())
			if err != nil {
				t.Fatalf("MarshalPublicKeyPEM: %v", err)
			}

			loadedSigner, err := LoadSignerPEM(privPEM)
			if err != nil {
				t.Fatalf("LoadSignerPEM: %v", err)
			}
			loadedVerifier, err := LoadVerifierPEM(pubPEM)
			if err != nil {
				t.Fatalf("LoadVerifierPEM: %v", err)
			}

			// The loaded key must have the same content-addressed ID...
			if loadedSigner.KeyID() != signer.KeyID() {
				t.Errorf("signer keyid changed across PEM round-trip")
			}
			if loadedVerifier.KeyID() != signer.KeyID() {
				t.Errorf("verifier keyid changed across PEM round-trip")
			}
			// ...and a signature from the reloaded private key must verify under
			// the reloaded public key.
			env, err := SignEnvelope("t", []byte("cross-check"), loadedSigner)
			if err != nil {
				t.Fatal(err)
			}
			if err := env.VerifyWith(loadedVerifier); err != nil {
				t.Fatalf("cross-verify after PEM round-trip: %v", err)
			}
		})
	}
}

// TestGenerateKeyDeterministic proves the injected reader controls key material:
// same seed, same key bytes; different seed, different key.
func TestGenerateKeyDeterministic(t *testing.T) {
	a := mustSigner(AlgEd25519, "same")
	b := mustSigner(AlgEd25519, "same")
	if a.KeyID() != b.KeyID() {
		t.Errorf("same seed produced different keys")
	}
	c := mustSigner(AlgEd25519, "different")
	if a.KeyID() == c.KeyID() {
		t.Errorf("different seeds produced the same key")
	}

	// The private PEM must also be byte-identical for a fixed seed.
	pa, _ := MarshalPrivateKeyPEM(a)
	pb, _ := MarshalPrivateKeyPEM(b)
	if !bytes.Equal(pa, pb) {
		t.Errorf("deterministic seed yielded different private PEM bytes")
	}
}

func TestLoadSignerRejectsGarbage(t *testing.T) {
	if _, err := LoadSignerPEM([]byte("not a pem")); err == nil {
		t.Error("LoadSignerPEM accepted non-PEM input")
	}
	if _, err := LoadVerifierPEM([]byte("not a pem")); err == nil {
		t.Error("LoadVerifierPEM accepted non-PEM input")
	}
}
