// Package sig re-implements the core of a Sigstore/Cosign-style signing stack
// on top of the Go standard library — no cosign, no sigstore, no external
// crypto. It provides:
//
//   - DSSE envelopes (Dead Simple Signing Envelope) with the standard PAE
//     pre-authentication encoding, so signatures cover a payload *and* its type;
//   - keyed signers/verifiers over ed25519 and ECDSA P-256, with PEM (PKCS#8 /
//     PKIX) serialization and content-addressed key IDs;
//   - a pluggable trust root plus an identity/issuer policy, so verification can
//     answer "who signed this?" and not merely "is the math valid?";
//   - a local, Rekor-style append-only transparency log (RFC 6962 Merkle tree)
//     with signed checkpoints and inclusion proofs, so an offline deployment
//     still gets tamper-evident signing records;
//   - a self-contained Bundle that carries envelopes + inclusion proofs, the
//     unit that gets attached to an image via OCI referrers and consumed by the
//     verify module.
//
// # Threat model (read before touching the verify path)
//
// The attacker controls the registry, the network, and any unsigned bytes. They
// may swap manifests, strip or replace signatures, replay old signatures onto a
// new digest, or present a valid signature made by an untrusted key. The verify
// path therefore fails closed: an empty/unknown trust root verifies nothing, a
// signature by a key not in the trust root is not "unsigned-but-ok" but a hard
// failure, and the subject digest a signature commits to is compared against the
// digest actually being verified (so a valid signature for image A never
// authenticates image B). Determinism: ed25519 is deterministic (RFC 8032) and
// tested byte-for-byte; ECDSA is randomized, so it is only round-trip tested.
package sig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
)

// Algorithm names a supported signature scheme.
type Algorithm string

const (
	// AlgEd25519 is EdDSA over Curve25519 (RFC 8032): deterministic signatures.
	AlgEd25519 Algorithm = "ed25519"
	// AlgECDSAP256 is ECDSA over NIST P-256 with SHA-256 digests. Signatures are
	// randomized, so they are verified by round-trip, never by byte-equality.
	AlgECDSAP256 Algorithm = "ecdsa-p256"
)

// Errors returned across the package. Callers gate on these with errors.Is.
var (
	// ErrVerify is the umbrella error for any failed verification. The verify
	// path deliberately collapses distinct failures into one class so callers
	// cannot accidentally treat "wrong key" more leniently than "bad math".
	ErrVerify = errors.New("signature verification failed")
	// ErrUntrusted means a signature is cryptographically valid but was made by
	// a key that is not in the trust root.
	ErrUntrusted = errors.New("no trusted key verified the signature")
	// ErrPolicy means verification succeeded but the signer identity or issuer
	// did not satisfy the configured policy.
	ErrPolicy = errors.New("signer did not satisfy policy")
)

// Signer produces signatures. Implementations wrap a private key and know their
// own public half so callers can publish a matching Verifier.
type Signer interface {
	// Sign returns a signature over msg. For ed25519 msg is signed directly; for
	// ECDSA msg is hashed with SHA-256 first. Callers pass the raw message (e.g.
	// a DSSE PAE), not a pre-hash.
	Sign(msg []byte) ([]byte, error)
	// Verifier returns the public verifier matching this signer.
	Verifier() Verifier
	// KeyID is the content-addressed identifier of the public key.
	KeyID() string
	// Algorithm reports the signature scheme.
	Algorithm() Algorithm
}

// Verifier checks signatures against a single public key.
type Verifier interface {
	// Verify returns nil if sig is a valid signature over msg for this key, and
	// an error wrapping ErrVerify otherwise.
	Verify(msg, sig []byte) error
	// KeyID is the content-addressed identifier of the public key.
	KeyID() string
	// Algorithm reports the signature scheme.
	Algorithm() Algorithm
	// PublicKey returns the underlying crypto.PublicKey, for serialization.
	PublicKey() crypto.PublicKey
}

// --- Content-addressed key IDs ---------------------------------------------

// KeyID derives a stable identifier for a public key: the hex-encoded SHA-256
// of its DER PKIX (SubjectPublicKeyInfo) encoding. Two processes that hold the
// same key compute the same ID with no coordination, which is exactly what a
// keyid field in a DSSE signature needs.
func KeyID(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key for keyid: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// algorithmFor reports the Algorithm implied by a public key's concrete type.
func algorithmFor(pub crypto.PublicKey) (Algorithm, error) {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return AlgEd25519, nil
	case *ecdsa.PublicKey:
		if k.Curve != nil && k.Curve.Params().Name == "P-256" {
			return AlgECDSAP256, nil
		}
		return "", fmt.Errorf("unsupported ECDSA curve %q (only P-256)", k.Curve.Params().Name)
	default:
		return "", fmt.Errorf("unsupported public key type %T", pub)
	}
}
