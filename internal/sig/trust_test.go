package sig

import (
	"errors"
	"testing"
)

func TestTrustRootVerify(t *testing.T) {
	signer := mustSigner(AlgEd25519, "trusted")
	env, err := SignEnvelope("t", []byte("payload"), signer)
	if err != nil {
		t.Fatal(err)
	}

	tr := NewTrustRoot()
	if err := tr.AddVerifier(signer.Verifier(), "ci@corp.example"); err != nil {
		t.Fatal(err)
	}

	res, err := tr.Verify(env, Policy{})
	if err != nil {
		t.Fatalf("Verify with trusted key: %v", err)
	}
	if res.Identity != "ci@corp.example" {
		t.Errorf("identity = %q, want ci@corp.example", res.Identity)
	}
}

// TestEmptyTrustRootFailsClosed is the security-critical default: no trust root
// means nothing verifies, even a cryptographically valid signature.
func TestEmptyTrustRootFailsClosed(t *testing.T) {
	signer := mustSigner(AlgEd25519, "orphan")
	env, _ := SignEnvelope("t", []byte("x"), signer)
	_, err := NewTrustRoot().Verify(env, Policy{})
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("empty trust root should fail ErrUntrusted, got %v", err)
	}
}

// TestUntrustedKeyRejected: a valid signature by a key not in the root fails.
func TestUntrustedKeyRejected(t *testing.T) {
	attacker := mustSigner(AlgEd25519, "attacker")
	env, _ := SignEnvelope("t", []byte("x"), attacker)

	tr := NewTrustRoot()
	_ = tr.AddVerifier(mustSigner(AlgEd25519, "legit").Verifier(), "legit")

	_, err := tr.Verify(env, Policy{})
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("untrusted key should fail ErrUntrusted, got %v", err)
	}
}

// TestPolicyIdentityEnforced: a trusted key whose identity is not on the policy
// allow-list is rejected with ErrPolicy — not silently accepted.
func TestPolicyIdentityEnforced(t *testing.T) {
	signer := mustSigner(AlgEd25519, "signer")
	env, _ := SignEnvelope("t", []byte("x"), signer)

	tr := NewTrustRoot()
	_ = tr.AddVerifier(signer.Verifier(), "intern@corp.example")

	// Allow only releases@corp.example.
	_, err := tr.Verify(env, Policy{Identities: []string{"releases@corp.example"}})
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("off-policy identity should fail ErrPolicy, got %v", err)
	}

	// The same signer, now on the allow-list, is accepted.
	res, err := tr.Verify(env, Policy{Identities: []string{"intern@corp.example"}})
	if err != nil {
		t.Fatalf("on-policy identity should verify: %v", err)
	}
	if res.Identity != "intern@corp.example" {
		t.Errorf("identity = %q", res.Identity)
	}
}

func TestTrustConfigRoundTrip(t *testing.T) {
	signer := mustSigner(AlgECDSAP256, "cfg")
	pubPEM, _ := MarshalPublicKeyPEM(signer.Verifier())

	cfg := TrustConfig{
		Keys: []TrustConfigKey{{
			PublicKeyPEM: string(pubPEM),
			Identity:     "builder@corp.example",
			Issuer:       "https://accounts.example.com",
		}},
		Policy: PolicyConfig{Identities: []string{"builder@corp.example"}},
	}
	// Marshal via the same JSON shape LoadTrustConfig expects.
	data := mustJSON(t, cfg)

	tr, pol, err := LoadTrustConfig(data)
	if err != nil {
		t.Fatalf("LoadTrustConfig: %v", err)
	}
	if tr.Len() != 1 {
		t.Fatalf("trust root size = %d", tr.Len())
	}
	env, _ := SignEnvelope("t", []byte("x"), signer)
	if _, err := tr.Verify(env, pol); err != nil {
		t.Fatalf("verify with loaded config: %v", err)
	}
}
