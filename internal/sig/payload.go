package sig

import (
	"encoding/json"
	"fmt"
	"strings"
)

// --- Simple-signing image payload ------------------------------------------
//
// Signing "an image" really means signing its manifest digest: the digest is
// the one value an attacker cannot change without changing the content. We use
// the Cosign "simple signing" payload shape so the thing we sign is explicit and
// interoperable — the signature commits to a specific digest and (optionally) a
// human-readable reference, and verification refuses any digest mismatch.

// SimpleSigningMediaType is the DSSE payload type for image signatures.
const SimpleSigningMediaType = "application/vnd.dev.cosign.simplesigning.v1+json"

// SimpleSigning is the payload that binds a signature to an image manifest
// digest. It mirrors Cosign's structure so the intent is unambiguous.
type SimpleSigning struct {
	Critical Critical          `json:"critical"`
	Optional map[string]string `json:"optional,omitempty"`
}

// Critical holds the fields that are, by definition, security-relevant: change
// any of them and the signature no longer applies.
type Critical struct {
	Identity CriticalIdentity `json:"identity"`
	Image    CriticalImage    `json:"image"`
	Type     string           `json:"type"`
}

// CriticalIdentity records the (mutable) reference the signer intended.
type CriticalIdentity struct {
	DockerReference string `json:"docker-reference"`
}

// CriticalImage records the (immutable) manifest digest being signed.
type CriticalImage struct {
	DockerManifestDigest string `json:"docker-manifest-digest"`
}

const criticalTypeImageSig = "cosign container image signature"

// NewImagePayload builds a simple-signing payload for a manifest digest and an
// optional human reference. The digest must be a full "sha256:<hex>" string;
// an empty or malformed digest is rejected rather than silently signed, because
// a signature over an empty digest authenticates nothing.
func NewImagePayload(dockerRef, manifestDigest string, optional map[string]string) ([]byte, error) {
	if err := validateDigest(manifestDigest); err != nil {
		return nil, err
	}
	p := SimpleSigning{
		Critical: Critical{
			Identity: CriticalIdentity{DockerReference: dockerRef},
			Image:    CriticalImage{DockerManifestDigest: manifestDigest},
			Type:     criticalTypeImageSig,
		},
		Optional: optional,
	}
	// json.Marshal on a struct emits fields in declaration order, so identical
	// inputs produce byte-identical payloads — needed for deterministic ed25519.
	data, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("marshal simple-signing payload: %w", err)
	}
	return data, nil
}

// ParseImagePayload decodes a simple-signing payload and validates its shape.
func ParseImagePayload(data []byte) (*SimpleSigning, error) {
	var p SimpleSigning
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parse simple-signing payload: %w", err)
	}
	if err := validateDigest(p.Critical.Image.DockerManifestDigest); err != nil {
		return nil, err
	}
	return &p, nil
}

// SignedDigest returns the manifest digest this payload commits to.
func (p *SimpleSigning) SignedDigest() string { return p.Critical.Image.DockerManifestDigest }

// validateDigest checks a digest is a well-formed "sha256:<64 hex>" string.
// Verifying against a malformed digest must fail closed, so we reject early.
func validateDigest(d string) error {
	alg, hex, ok := strings.Cut(d, ":")
	if !ok {
		return fmt.Errorf("malformed digest %q: want algo:hex", d)
	}
	if alg != "sha256" {
		return fmt.Errorf("unsupported digest algorithm %q (only sha256)", alg)
	}
	if len(hex) != 64 {
		return fmt.Errorf("malformed sha256 digest %q: want 64 hex chars, got %d", d, len(hex))
	}
	for _, c := range hex {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("malformed sha256 digest %q: non-hex character", d)
		}
	}
	return nil
}

// ValidateDigest is the exported form of the digest check, reused by callers
// (registry, attest) that accept digests from untrusted input.
func ValidateDigest(d string) error { return validateDigest(d) }
