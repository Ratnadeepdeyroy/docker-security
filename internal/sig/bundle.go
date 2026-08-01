package sig

import (
	"encoding/json"
	"fmt"
)

// --- Verification bundle ----------------------------------------------------
//
// A Bundle is the self-contained artifact that travels with an image: the DSSE
// envelopes (signatures and/or attestations) plus, for each, an optional
// transparency-log inclusion proof. It is what gets attached to a registry via
// an OCI referrer and what the verify module consumes offline. Bundling the
// proof with the envelope means a verifier needs only the bundle and its trust
// root — no network, no live log — which is the whole point of the offline path.

// Bundle carries verifiable material bound to a single subject digest.
type Bundle struct {
	// MediaType identifies this as a docker-security verification bundle.
	MediaType string `json:"mediaType"`
	// SubjectDigest is the image manifest digest ("sha256:<hex>") the entries
	// pertain to. Verifiers cross-check this against the digest under test.
	SubjectDigest string `json:"subjectDigest"`
	// Entries holds the signatures/attestations.
	Entries []BundleEntry `json:"entries"`
}

// BundleEntry is one envelope with optional log proof and a kind tag.
type BundleEntry struct {
	// Kind is "signature" or "attestation" (informational; verification keys off
	// the envelope's payload type, not this tag).
	Kind string `json:"kind"`
	// Envelope is the DSSE envelope.
	Envelope *Envelope `json:"envelope"`
	// Inclusion is the transparency-log proof for Envelope, if logged.
	Inclusion *InclusionRecord `json:"inclusion,omitempty"`
}

// BundleMediaType is the artifact type used for the bundle and its OCI referrer.
const BundleMediaType = "application/vnd.docker-security.bundle.v1+json"

// KindSignature and KindAttestation label bundle entries.
const (
	KindSignature   = "signature"
	KindAttestation = "attestation"
)

// NewBundle starts an empty bundle for a subject digest.
func NewBundle(subjectDigest string) (*Bundle, error) {
	if err := validateDigest(subjectDigest); err != nil {
		return nil, err
	}
	return &Bundle{MediaType: BundleMediaType, SubjectDigest: subjectDigest}, nil
}

// AddSignature appends a signature envelope (with optional inclusion proof).
func (b *Bundle) AddSignature(env *Envelope, inc *InclusionRecord) {
	b.Entries = append(b.Entries, BundleEntry{Kind: KindSignature, Envelope: env, Inclusion: inc})
}

// AddAttestation appends an attestation envelope (with optional inclusion proof).
func (b *Bundle) AddAttestation(env *Envelope, inc *InclusionRecord) {
	b.Entries = append(b.Entries, BundleEntry{Kind: KindAttestation, Envelope: env, Inclusion: inc})
}

// Marshal renders the bundle as indented JSON (it is small and often reviewed by
// humans, so readability beats compactness here).
func (b *Bundle) Marshal() ([]byte, error) {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal bundle: %w", err)
	}
	return data, nil
}

// ParseBundle decodes and shape-checks a bundle.
func ParseBundle(data []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}
	if b.SubjectDigest == "" {
		return nil, fmt.Errorf("bundle: missing subjectDigest")
	}
	if err := validateDigest(b.SubjectDigest); err != nil {
		return nil, err
	}
	for i, e := range b.Entries {
		if e.Envelope == nil {
			return nil, fmt.Errorf("bundle entry %d: missing envelope", i)
		}
	}
	return &b, nil
}
