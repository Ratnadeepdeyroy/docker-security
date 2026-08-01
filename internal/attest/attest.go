// Package attest builds and verifies in-toto attestations wrapped in DSSE
// envelopes, re-implemented on internal/sig (no in-toto or sigstore libraries).
// An attestation is a signed statement *about* an artifact: "this digest has
// this SBOM", "this digest was built by this pipeline" (SLSA provenance), "this
// digest is not affected by CVE-X" (VEX), or — for the agentic era — "agent X,
// running prompt hash Y, produced this digest" (an agent-action attestation).
//
// The unit that ties everything together is the in-toto Statement: a subject
// (name + digest) plus a typed predicate. Signing wraps the Statement JSON in a
// DSSE envelope with the in-toto payload type; verifying unwraps it, checks the
// signature against a trust root and policy, and then — critically — checks that
// the statement's subject digest matches the artifact actually under test.
// Skipping that last check is how a valid attestation for image A gets replayed
// onto image B, so the verify path treats a subject mismatch as a hard failure.
package attest

import (
	"encoding/json"
	"fmt"

	"github.com/Ratnadeepdeyroy/docker-security/internal/sig"
)

// InTotoStatementType is the type URI for an in-toto v1 Statement.
const InTotoStatementType = "https://in-toto.io/Statement/v1"

// InTotoPayloadType is the DSSE payload type for in-toto attestations.
const InTotoPayloadType = "application/vnd.in-toto+json"

// Predicate type URIs for the predicates this package understands.
const (
	PredicateSLSAProvenance = "https://slsa.dev/provenance/v1"
	PredicateVSA            = "https://slsa.dev/verification_summary/v1"
	PredicateOpenVEX        = "https://openvex.dev/ns/v0.2.0"
	PredicateCycloneDX      = "https://cyclonedx.org/bom"
	PredicateSPDX           = "https://spdx.dev/Document"
	// PredicateAgentAction is this project's own predicate for attesting an
	// automated (AI-agent) infrastructure change. It is intentionally namespaced
	// under docker-security.dev to signal it is a local extension, not a standard.
	PredicateAgentAction = "https://docker-security.dev/attestations/agent-action/v0.1"
)

// Subject is the artifact an attestation is about: a name plus one or more
// digests keyed by algorithm (e.g. {"sha256": "<hex>"}).
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Statement is an in-toto v1 statement. The predicate is held as raw JSON so a
// verifier can check the type and subject without needing to understand every
// predicate schema — unknown predicate shapes still verify cryptographically.
type Statement struct {
	Type          string          `json:"_type"`
	Subject       []Subject       `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// NewStatement assembles a statement binding a subject digest to a typed
// predicate. subjectDigest must be a full "sha256:<hex>" string; the value is
// stored split into {"sha256": "<hex>"} per the in-toto schema. A malformed
// digest is rejected so we never emit an attestation about "nothing".
func NewStatement(subjectName, subjectDigest, predicateType string, predicate any) (*Statement, error) {
	if err := sig.ValidateDigest(subjectDigest); err != nil {
		return nil, fmt.Errorf("attestation subject: %w", err)
	}
	alg, hexDigest := splitDigest(subjectDigest)
	raw, err := marshalPredicate(predicate)
	if err != nil {
		return nil, err
	}
	return &Statement{
		Type:          InTotoStatementType,
		Subject:       []Subject{{Name: subjectName, Digest: map[string]string{alg: hexDigest}}},
		PredicateType: predicateType,
		Predicate:     raw,
	}, nil
}

// marshalPredicate accepts either raw JSON (passed through) or any value to be
// marshaled, so callers can supply a struct or pre-serialized bytes (e.g. an
// SBOM document that is already JSON).
func marshalPredicate(predicate any) (json.RawMessage, error) {
	switch p := predicate.(type) {
	case json.RawMessage:
		return p, nil
	case []byte:
		return json.RawMessage(p), nil
	default:
		data, err := json.Marshal(predicate)
		if err != nil {
			return nil, fmt.Errorf("marshal predicate: %w", err)
		}
		return data, nil
	}
}

// Marshal serializes the statement as canonical JSON (the bytes that get signed
// inside the DSSE envelope).
func (s *Statement) Marshal() ([]byte, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("marshal in-toto statement: %w", err)
	}
	return data, nil
}

// ParseStatement decodes and shape-checks an in-toto statement.
func ParseStatement(data []byte) (*Statement, error) {
	var s Statement
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse in-toto statement: %w", err)
	}
	if s.Type != InTotoStatementType {
		return nil, fmt.Errorf("unexpected statement type %q (want %q)", s.Type, InTotoStatementType)
	}
	if len(s.Subject) == 0 {
		return nil, fmt.Errorf("statement has no subject")
	}
	return &s, nil
}

// SubjectDigest returns the first subject's "sha256:<hex>" digest, or "" if the
// statement carries no sha256 subject digest.
func (s *Statement) SubjectDigest() string {
	for _, sub := range s.Subject {
		if h, ok := sub.Digest["sha256"]; ok {
			return "sha256:" + h
		}
	}
	return ""
}

// Sign wraps a statement in a DSSE envelope signed by the given signers.
func Sign(st *Statement, signers ...sig.Signer) (*sig.Envelope, error) {
	body, err := st.Marshal()
	if err != nil {
		return nil, err
	}
	return sig.SignEnvelope(InTotoPayloadType, body, signers...)
}

func splitDigest(d string) (alg, hexPart string) {
	for i := 0; i < len(d); i++ {
		if d[i] == ':' {
			return d[:i], d[i+1:]
		}
	}
	return "sha256", d
}
