package attest

import (
	"encoding/json"
	"fmt"

	"github.com/Ratnadeepdeyroy/docker-security/internal/sig"
)

// --- Attestation verification ----------------------------------------------
//
// Verifying an attestation is a sequence of AND-ed checks, each of which an
// attacker would love you to skip:
//
//  1. The DSSE envelope is signed by a trusted key that satisfies policy.
//  2. The envelope's payload type really is an in-toto statement.
//  3. The statement's subject digest matches the artifact under test — this is
//     the anti-replay check; without it a valid attestation for image A
//     authenticates image B.
//  4. (When required) the predicate type is the one the caller demanded, so a
//     provenance attestation cannot be accepted where an SBOM was required.
//
// Any failure returns an error; there is no partial success. The verified
// identity is returned so callers can log/report who vouched for the artifact.

// Requirement describes what a caller demands of an attestation.
type Requirement struct {
	// ExpectedDigest is the "sha256:<hex>" the statement's subject must match.
	// Required — an empty expected digest is a programming error, not "any".
	ExpectedDigest string
	// PredicateType, if set, is the exact predicate type that must be present.
	PredicateType string
	// Policy constrains the acceptable signer identity/issuer.
	Policy sig.Policy
}

// Result reports a successful attestation verification.
type Result struct {
	// Signer is the trust-root outcome (which key/identity vouched).
	Signer sig.VerifyResult
	// Statement is the verified in-toto statement (predicate available raw).
	Statement *Statement
}

// Verify checks a DSSE-wrapped attestation against a trust root and a
// requirement. It fails closed on any mismatch.
func Verify(env *sig.Envelope, trust *sig.TrustRoot, req Requirement) (*Result, error) {
	if req.ExpectedDigest == "" {
		return nil, fmt.Errorf("attestation verify: ExpectedDigest is required")
	}
	if err := sig.ValidateDigest(req.ExpectedDigest); err != nil {
		return nil, fmt.Errorf("attestation verify: %w", err)
	}

	// (1) Signature + trust + policy.
	signer, err := trust.Verify(env, req.Policy)
	if err != nil {
		return nil, err // already wrapped as ErrUntrusted / ErrPolicy
	}

	// (2) It must be an in-toto statement.
	if env.PayloadType != InTotoPayloadType {
		return nil, fmt.Errorf("attestation verify: payload type %q is not in-toto: %w", env.PayloadType, sig.ErrVerify)
	}
	payload, err := env.DecodePayload()
	if err != nil {
		return nil, err
	}
	st, err := ParseStatement(payload)
	if err != nil {
		return nil, fmt.Errorf("attestation verify: %w", err)
	}

	// (3) Subject digest must match the artifact under test (anti-replay).
	if !st.hasSubjectDigest(req.ExpectedDigest) {
		return nil, fmt.Errorf("attestation verify: subject digest %s does not match expected %s: %w",
			st.SubjectDigest(), req.ExpectedDigest, sig.ErrVerify)
	}

	// (4) Predicate type, when demanded.
	if req.PredicateType != "" && st.PredicateType != req.PredicateType {
		return nil, fmt.Errorf("attestation verify: predicate type %q != required %q: %w",
			st.PredicateType, req.PredicateType, sig.ErrVerify)
	}

	return &Result{Signer: signer, Statement: st}, nil
}

// hasSubjectDigest reports whether any subject carries the given
// "sha256:<hex>" digest. It compares by (algorithm, value) pairs so a match on
// a different algorithm's field never counts.
func (s *Statement) hasSubjectDigest(want string) bool {
	wantAlg, wantHex := splitDigest(want)
	for _, sub := range s.Subject {
		if got, ok := sub.Digest[wantAlg]; ok && got == wantHex {
			return true
		}
	}
	return false
}

// DecodePredicate unmarshals the statement's predicate into v. It is a
// convenience for callers that, after verification, want the typed predicate
// (e.g. to read a provenance builder ID or a VEX status).
func (s *Statement) DecodePredicate(v any) error {
	if len(s.Predicate) == 0 {
		return fmt.Errorf("statement has no predicate")
	}
	if err := json.Unmarshal(s.Predicate, v); err != nil {
		return fmt.Errorf("decode predicate: %w", err)
	}
	return nil
}
