package attest

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/sig"
)

const testDigest = "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
const otherDigest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// detReader mirrors the sig package's deterministic reader so attest tests can
// generate reproducible keys without importing test-only symbols.
type detReader struct {
	seed []byte
	buf  []byte
	ctr  uint64
}

func newDetReader(seed string) *detReader { return &detReader{seed: []byte(seed)} }

func (r *detReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(r.buf) == 0 {
			var c [8]byte
			binary.BigEndian.PutUint64(c[:], r.ctr)
			r.ctr++
			sum := sha256.Sum256(append(append([]byte{}, r.seed...), c[:]...))
			r.buf = sum[:]
		}
		m := copy(p[n:], r.buf)
		r.buf = r.buf[m:]
		n += m
	}
	return n, nil
}

func mustSigner(t *testing.T, seed string) sig.Signer {
	t.Helper()
	s, err := sig.GenerateKey(sig.AlgEd25519, newDetReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func trustOf(t *testing.T, signer sig.Signer, identity string) *sig.TrustRoot {
	t.Helper()
	tr := sig.NewTrustRoot()
	if err := tr.AddVerifier(signer.Verifier(), identity); err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestProvenanceRoundTripAndVerify(t *testing.T) {
	signer := mustSigner(t, "prov")
	prov := SLSAProvenance{
		BuildDefinition: BuildDefinition{
			BuildType:          "https://docker-security.dev/buildtypes/demo",
			ExternalParameters: map[string]string{"source": "git+https://example.com/app@refs/heads/main"},
		},
		RunDetails: RunDetails{Builder: Builder{ID: "https://ci.example.com/runner"}},
	}
	st, err := NewStatement("app", testDigest, PredicateSLSAProvenance, prov)
	if err != nil {
		t.Fatalf("NewStatement: %v", err)
	}
	env, err := Sign(st, signer)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	trust := trustOf(t, signer, "builder@corp.example")
	res, err := Verify(env, trust, Requirement{
		ExpectedDigest: testDigest,
		PredicateType:  PredicateSLSAProvenance,
		Policy:         sig.Policy{Identities: []string{"builder@corp.example"}},
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Signer.Identity != "builder@corp.example" {
		t.Errorf("signer identity = %q", res.Signer.Identity)
	}
	// The typed predicate must survive the round-trip.
	var got SLSAProvenance
	if err := res.Statement.DecodePredicate(&got); err != nil {
		t.Fatal(err)
	}
	if got.RunDetails.Builder.ID != "https://ci.example.com/runner" {
		t.Errorf("builder id lost: %q", got.RunDetails.Builder.ID)
	}
}

// TestVerifyRejectsDigestReplay is the anti-replay check: a valid attestation
// for one digest must not verify against a different digest.
func TestVerifyRejectsDigestReplay(t *testing.T) {
	signer := mustSigner(t, "replay")
	st, _ := NewStatement("app", testDigest, PredicateSLSAProvenance, SLSAProvenance{})
	env, _ := Sign(st, signer)

	trust := trustOf(t, signer, "id")
	_, err := Verify(env, trust, Requirement{ExpectedDigest: otherDigest})
	if !errors.Is(err, sig.ErrVerify) {
		t.Fatalf("digest replay should fail ErrVerify, got %v", err)
	}
}

// TestVerifyRejectsPredicateMismatch: a provenance attestation must not satisfy
// a requirement that demands an SBOM.
func TestVerifyRejectsPredicateMismatch(t *testing.T) {
	signer := mustSigner(t, "predmismatch")
	st, _ := NewStatement("app", testDigest, PredicateSLSAProvenance, SLSAProvenance{})
	env, _ := Sign(st, signer)

	trust := trustOf(t, signer, "id")
	_, err := Verify(env, trust, Requirement{ExpectedDigest: testDigest, PredicateType: PredicateCycloneDX})
	if !errors.Is(err, sig.ErrVerify) {
		t.Fatalf("predicate mismatch should fail ErrVerify, got %v", err)
	}
}

// TestVerifyRejectsUntrustedSigner: a valid attestation from an untrusted key
// must be rejected.
func TestVerifyRejectsUntrustedSigner(t *testing.T) {
	attacker := mustSigner(t, "attacker")
	st, _ := NewStatement("app", testDigest, PredicateSLSAProvenance, SLSAProvenance{})
	env, _ := Sign(st, attacker)

	trust := trustOf(t, mustSigner(t, "legit"), "legit")
	_, err := Verify(env, trust, Requirement{ExpectedDigest: testDigest})
	if !errors.Is(err, sig.ErrUntrusted) {
		t.Fatalf("untrusted signer should fail ErrUntrusted, got %v", err)
	}
}

func TestNewStatementRejectsBadDigest(t *testing.T) {
	if _, err := NewStatement("app", "not-a-digest", PredicateSLSAProvenance, SLSAProvenance{}); err == nil {
		t.Error("NewStatement accepted a malformed subject digest")
	}
}

func TestSBOMStatement(t *testing.T) {
	signer := mustSigner(t, "sbom")
	sbomDoc := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`)
	st, err := NewSBOMStatement("app", testDigest, "cyclonedx", sbomDoc)
	if err != nil {
		t.Fatalf("NewSBOMStatement: %v", err)
	}
	if st.PredicateType != PredicateCycloneDX {
		t.Errorf("predicate type = %q", st.PredicateType)
	}
	env, _ := Sign(st, signer)
	trust := trustOf(t, signer, "id")
	res, err := Verify(env, trust, Requirement{ExpectedDigest: testDigest, PredicateType: PredicateCycloneDX})
	if err != nil {
		t.Fatalf("Verify SBOM attestation: %v", err)
	}
	// The embedded SBOM predicate must be exactly what we bound.
	var back map[string]any
	if err := res.Statement.DecodePredicate(&back); err != nil {
		t.Fatal(err)
	}
	if back["bomFormat"] != "CycloneDX" {
		t.Errorf("SBOM predicate corrupted: %v", back)
	}
}

func TestSBOMStatementRejectsNonJSON(t *testing.T) {
	if _, err := NewSBOMStatement("app", testDigest, "cyclonedx", []byte("not json")); err == nil {
		t.Error("NewSBOMStatement accepted non-JSON predicate")
	}
}

func TestVEXPredicate(t *testing.T) {
	vex := OpenVEX{
		Context:   "https://openvex.dev/ns/v0.2.0",
		ID:        "https://example.com/vex/1",
		Author:    "security@corp.example",
		Timestamp: time.Unix(1700000000, 0).UTC(),
		Version:   1,
		Statements: []VEXStatement{{
			Vulnerability: VEXVuln{Name: "CVE-2024-0001"},
			Products:      []string{testDigest},
			Status:        VEXNotAffected,
			Justification: "vulnerable_code_not_in_execute_path",
		}},
	}
	st, err := NewStatement("app", testDigest, PredicateOpenVEX, vex)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := st.Marshal()
	// Round-trip through parse and confirm the VEX status is readable.
	parsed, err := ParseStatement(data)
	if err != nil {
		t.Fatal(err)
	}
	var got OpenVEX
	if err := parsed.DecodePredicate(&got); err != nil {
		t.Fatal(err)
	}
	if got.Statements[0].Status != VEXNotAffected {
		t.Errorf("VEX status lost: %q", got.Statements[0].Status)
	}
	_ = json.Valid(data)
}
