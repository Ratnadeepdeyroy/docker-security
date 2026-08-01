package sig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

// --- Concrete signers / verifiers ------------------------------------------

// ed25519Signer signs with an Ed25519 private key. Signatures are deterministic.
type ed25519Signer struct {
	priv  ed25519.PrivateKey
	keyID string
}

func (s *ed25519Signer) Sign(msg []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, msg), nil
}
func (s *ed25519Signer) Verifier() Verifier {
	return &ed25519Verifier{pub: s.priv.Public().(ed25519.PublicKey), keyID: s.keyID}
}
func (s *ed25519Signer) KeyID() string        { return s.keyID }
func (s *ed25519Signer) Algorithm() Algorithm { return AlgEd25519 }

// ed25519Verifier verifies Ed25519 signatures.
type ed25519Verifier struct {
	pub   ed25519.PublicKey
	keyID string
}

func (v *ed25519Verifier) Verify(msg, sig []byte) error {
	if !ed25519.Verify(v.pub, msg, sig) {
		return fmt.Errorf("ed25519 %s: %w", short(v.keyID), ErrVerify)
	}
	return nil
}
func (v *ed25519Verifier) KeyID() string               { return v.keyID }
func (v *ed25519Verifier) Algorithm() Algorithm        { return AlgEd25519 }
func (v *ed25519Verifier) PublicKey() crypto.PublicKey { return v.pub }

// ecdsaSigner signs with an ECDSA P-256 private key over a SHA-256 digest.
type ecdsaSigner struct {
	priv  *ecdsa.PrivateKey
	keyID string
	// randr is the entropy source for signing; injectable so tests are
	// reproducible even though ECDSA itself is randomized.
	randr io.Reader
}

func (s *ecdsaSigner) Sign(msg []byte) ([]byte, error) {
	digest := sha256.Sum256(msg)
	r := s.randr
	if r == nil {
		r = rand.Reader
	}
	sig, err := ecdsa.SignASN1(r, s.priv, digest[:])
	if err != nil {
		return nil, fmt.Errorf("ecdsa sign: %w", err)
	}
	return sig, nil
}
func (s *ecdsaSigner) Verifier() Verifier {
	return &ecdsaVerifier{pub: &s.priv.PublicKey, keyID: s.keyID}
}
func (s *ecdsaSigner) KeyID() string        { return s.keyID }
func (s *ecdsaSigner) Algorithm() Algorithm { return AlgECDSAP256 }

// ecdsaVerifier verifies ECDSA P-256 signatures.
type ecdsaVerifier struct {
	pub   *ecdsa.PublicKey
	keyID string
}

func (v *ecdsaVerifier) Verify(msg, sig []byte) error {
	digest := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(v.pub, digest[:], sig) {
		return fmt.Errorf("ecdsa %s: %w", short(v.keyID), ErrVerify)
	}
	return nil
}
func (v *ecdsaVerifier) KeyID() string               { return v.keyID }
func (v *ecdsaVerifier) Algorithm() Algorithm        { return AlgECDSAP256 }
func (v *ecdsaVerifier) PublicKey() crypto.PublicKey { return v.pub }

// --- Key generation ---------------------------------------------------------

// GenerateKey creates a new signer for the given algorithm, drawing entropy
// from randr. Passing a fixed reader yields deterministic keys, which is how the
// test suite gets reproducible fixtures without committing secrets it must then
// rotate. In production, pass crypto/rand.Reader (or nil, which defaults to it).
func GenerateKey(alg Algorithm, randr io.Reader) (Signer, error) {
	if randr == nil {
		randr = rand.Reader
	}
	switch alg {
	case AlgEd25519:
		pub, priv, err := ed25519.GenerateKey(randr)
		if err != nil {
			return nil, fmt.Errorf("generate ed25519 key: %w", err)
		}
		id, err := KeyID(pub)
		if err != nil {
			return nil, err
		}
		return &ed25519Signer{priv: priv, keyID: id}, nil
	case AlgECDSAP256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), randr)
		if err != nil {
			return nil, fmt.Errorf("generate ecdsa key: %w", err)
		}
		id, err := KeyID(&priv.PublicKey)
		if err != nil {
			return nil, err
		}
		return &ecdsaSigner{priv: priv, keyID: id, randr: randr}, nil
	default:
		return nil, fmt.Errorf("unknown algorithm %q", alg)
	}
}

// signerFromECDSA wraps an existing ECDSA P-256 private key as a Signer. It is
// used when the key is created outside GenerateKey — e.g. an ephemeral key that
// a certificate is issued for (cosign keyless), where x509 owns key creation.
func signerFromECDSA(priv *ecdsa.PrivateKey) (Signer, error) {
	if priv.Curve.Params().Name != "P-256" {
		return nil, fmt.Errorf("unsupported ECDSA curve %q (only P-256)", priv.Curve.Params().Name)
	}
	id, err := KeyID(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &ecdsaSigner{priv: priv, keyID: id}, nil
}

// --- PEM (de)serialization ---------------------------------------------------

// MarshalPrivateKeyPEM encodes a signer's private key as a PKCS#8 PEM block.
func MarshalPrivateKeyPEM(s Signer) ([]byte, error) {
	var key crypto.PrivateKey
	switch v := s.(type) {
	case *ed25519Signer:
		key = v.priv
	case *ecdsaSigner:
		key = v.priv
	default:
		return nil, fmt.Errorf("cannot marshal signer of type %T", s)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal pkcs8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// MarshalPublicKeyPEM encodes a verifier's public key as a PKIX PEM block.
func MarshalPublicKeyPEM(v Verifier) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(v.PublicKey())
	if err != nil {
		return nil, fmt.Errorf("marshal pkix: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// LoadSignerPEM parses a PKCS#8 private-key PEM block into a Signer.
func LoadSignerPEM(pemBytes []byte) (Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8 private key: %w", err)
	}
	switch k := key.(type) {
	case ed25519.PrivateKey:
		id, err := KeyID(k.Public())
		if err != nil {
			return nil, err
		}
		return &ed25519Signer{priv: k, keyID: id}, nil
	case *ecdsa.PrivateKey:
		if k.Curve.Params().Name != "P-256" {
			return nil, fmt.Errorf("unsupported ECDSA curve %q (only P-256)", k.Curve.Params().Name)
		}
		id, err := KeyID(&k.PublicKey)
		if err != nil {
			return nil, err
		}
		return &ecdsaSigner{priv: k, keyID: id}, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
}

// LoadVerifierPEM parses a PKIX public-key PEM block into a Verifier.
func LoadVerifierPEM(pemBytes []byte) (Verifier, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkix public key: %w", err)
	}
	return VerifierFromPublicKey(pub)
}

// VerifierFromPublicKey wraps an already-parsed public key in a Verifier.
func VerifierFromPublicKey(pub crypto.PublicKey) (Verifier, error) {
	alg, err := algorithmFor(pub)
	if err != nil {
		return nil, err
	}
	id, err := KeyID(pub)
	if err != nil {
		return nil, err
	}
	switch alg {
	case AlgEd25519:
		return &ed25519Verifier{pub: pub.(ed25519.PublicKey), keyID: id}, nil
	case AlgECDSAP256:
		return &ecdsaVerifier{pub: pub.(*ecdsa.PublicKey), keyID: id}, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm %q", alg)
	}
}

// short trims a key ID for use in error messages; full IDs are 64 hex chars.
func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
