package sig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"testing"
	"time"
)

// fulcioFixture builds a self-signed CA and a leaf certificate that carries a SAN
// identity and the Fulcio OIDC-issuer extension, plus a signer for the leaf key.
// It emulates exactly what Fulcio issues for a keyless signature, letting us test
// cosign verification end-to-end with no network.
type fulcioFixture struct {
	rootPEM []byte
	leafPEM []byte
	signer  Signer
}

func newFulcioFixture(t *testing.T, subjectURI, issuer string, notBefore time.Time) fulcioFixture {
	t.Helper()

	// CA.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-fulcio-root"},
		NotBefore:             notBefore.Add(-time.Hour),
		NotAfter:              notBefore.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	// Leaf key (the ephemeral cosign signing key).
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse(subjectURI)
	issuerExt := pkix.Extension{Id: oidFulcioIssuerV1, Value: []byte(issuer)}
	leafTmpl := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{},
		NotBefore:       notBefore,
		NotAfter:        notBefore.Add(10 * time.Minute), // short-lived, like Fulcio
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		URIs:            []*url.URL{uri},
		ExtraExtensions: []pkix.Extension{issuerExt},
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := signerFromECDSA(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	return fulcioFixture{
		rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		leafPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		signer:  signer,
	}
}

func TestCosignVerifyHappyPath(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	subject := "https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v1"
	issuer := "https://token.actions.githubusercontent.com"
	fx := newFulcioFixture(t, subject, issuer, now)

	payload, err := NewImagePayload("ghcr.io/acme/app:v1", "sha256:"+hex64('a'), nil)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := fx.signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}

	v, err := NewCosignVerifier(fx.rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	pol := CosignPolicy{CertificateIdentity: subject, CertificateOIDCIssuer: issuer}
	id, err := v.VerifyImageSignature(fx.leafPEM, payload, signature, pol, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.SubjectID != subject {
		t.Errorf("SubjectID = %q, want %q", id.SubjectID, subject)
	}
	if id.Issuer != issuer {
		t.Errorf("Issuer = %q, want %q", id.Issuer, issuer)
	}
}

func TestCosignVerifyRejectsWrongIdentity(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	fx := newFulcioFixture(t, "https://github.com/acme/app/wf.yml@main", "https://issuer", now)
	payload, _ := NewImagePayload("ref", "sha256:"+hex64('b'), nil)
	sig, _ := fx.signer.Sign(payload)
	v, _ := NewCosignVerifier(fx.rootPEM)

	pol := CosignPolicy{CertificateIdentity: "https://github.com/evil/repo/wf.yml@main"}
	_, err := v.VerifyImageSignature(fx.leafPEM, payload, sig, pol, now)
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("expected ErrPolicy for wrong identity, got %v", err)
	}
}

func TestCosignVerifyRejectsWrongIssuer(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	fx := newFulcioFixture(t, "sub", "https://real-issuer", now)
	payload, _ := NewImagePayload("ref", "sha256:"+hex64('c'), nil)
	sig, _ := fx.signer.Sign(payload)
	v, _ := NewCosignVerifier(fx.rootPEM)

	_, err := v.VerifyImageSignature(fx.leafPEM, payload, sig, CosignPolicy{CertificateOIDCIssuer: "https://fake-issuer"}, now)
	if !errors.Is(err, ErrPolicy) {
		t.Fatalf("expected ErrPolicy for wrong issuer, got %v", err)
	}
}

func TestCosignVerifyRejectsUntrustedCA(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	signed := newFulcioFixture(t, "sub", "iss", now)
	other := newFulcioFixture(t, "sub", "iss", now) // different CA
	payload, _ := NewImagePayload("ref", "sha256:"+hex64('d'), nil)
	sig, _ := signed.signer.Sign(payload)

	// Verifier trusts only the OTHER CA → the signed leaf must not chain.
	v, _ := NewCosignVerifier(other.rootPEM)
	_, err := v.VerifyImageSignature(signed.leafPEM, payload, sig, CosignPolicy{}, now)
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("expected ErrUntrusted for foreign CA, got %v", err)
	}
}

func TestCosignVerifyRejectsTamperedPayload(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	fx := newFulcioFixture(t, "sub", "iss", now)
	payload, _ := NewImagePayload("ref", "sha256:"+hex64('e'), nil)
	sig, _ := fx.signer.Sign(payload)
	v, _ := NewCosignVerifier(fx.rootPEM)

	tampered, _ := NewImagePayload("ref", "sha256:"+hex64('f'), nil)
	_, err := v.VerifyImageSignature(fx.leafPEM, tampered, sig, CosignPolicy{}, now)
	if !errors.Is(err, ErrVerify) {
		t.Fatalf("expected ErrVerify for tampered payload, got %v", err)
	}
}

func TestCosignIdentityPrefixMatch(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	subject := "https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v2"
	fx := newFulcioFixture(t, subject, "iss", now)
	payload, _ := NewImagePayload("ref", "sha256:"+hex64('1'), nil)
	sig, _ := fx.signer.Sign(payload)
	v, _ := NewCosignVerifier(fx.rootPEM)

	// A prefix policy (any tag under this workflow) accepts the tag-specific SAN.
	pol := CosignPolicy{CertificateIdentity: "https://github.com/acme/app/.github/workflows/release.yml@*"}
	if _, err := v.VerifyImageSignature(fx.leafPEM, payload, sig, pol, now); err != nil {
		t.Fatalf("prefix identity match should verify, got %v", err)
	}
}

func TestFulcioIssuerV2Extension(t *testing.T) {
	// The v2 issuer extension wraps the value in a DER UTF8String; confirm we
	// decode it. Build a cert with only the v2 extension.
	der, _ := asn1.Marshal("https://v2-issuer.example")
	c := &x509.Certificate{Extensions: []pkix.Extension{{Id: oidFulcioIssuerV2, Value: der}}}
	if got := identityFromCert(c).Issuer; got != "https://v2-issuer.example" {
		t.Errorf("v2 issuer decode = %q", got)
	}
}

// hex64 returns a 64-char hex string of a repeated nibble, for building valid
// sha256 digests in tests.
func hex64(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
