package attest

import (
	"encoding/json"
	"fmt"
)

// --- SBOM attestation -------------------------------------------------------
//
// An SBOM on its own is an unsigned claim about an image's contents. Binding it
// to the image's digest inside a signed in-toto statement turns it into
// evidence: a verifier can prove "this exact SBOM was asserted, by this signer,
// for this exact image". We keep the SBOM bytes opaque (json.RawMessage) so this
// package does not depend on the sbom package — the caller (the verify module or
// `dsecrat attest`) generates the SBOM and hands us its serialized form.

// SBOMPredicateType returns the in-toto predicate type URI for an SBOM format
// name ("cyclonedx" or "spdx"). Unknown formats map to CycloneDX, which is the
// project's default SBOM encoding.
func SBOMPredicateType(format string) string {
	switch format {
	case "spdx":
		return PredicateSPDX
	default:
		return PredicateCycloneDX
	}
}

// NewSBOMStatement binds a serialized SBOM document to an image digest as an
// in-toto statement. sbomJSON must be a valid JSON document (an SPDX or
// CycloneDX BOM); it becomes the statement's predicate verbatim.
func NewSBOMStatement(subjectName, subjectDigest, format string, sbomJSON []byte) (*Statement, error) {
	if !json.Valid(sbomJSON) {
		return nil, fmt.Errorf("SBOM predicate is not valid JSON")
	}
	return NewStatement(subjectName, subjectDigest, SBOMPredicateType(format), json.RawMessage(sbomJSON))
}
