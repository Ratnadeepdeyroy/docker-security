package sig

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// --- Cosign keyless (Fulcio) verification -----------------------------------
//
// Cosign "keyless" signing does not use a long-lived key: a CI job authenticates
// to an OIDC provider, Fulcio issues a short-lived X.509 certificate binding that
// OIDC identity (email / SPIFFE / GitHub-Actions URI) to an ephemeral key, the
// job signs the simple-signing payload with that key, and the signature +
// certificate + a Rekor transparency-log entry are published as OCI referrers.
//
// Verifying such a signature — the common case for images in the wild — means:
//  1. the certificate chains to a trusted Fulcio root (and was valid at signing);
//  2. the SAN identity and the OIDC-issuer extension match the expected signer;
//  3. the signature is valid over the payload under the certificate's key;
//  4. (optionally) a Rekor inclusion proof shows the entry was logged.
//
// This file implements that with only crypto/x509 + the existing DSSE/Merkle
// primitives — no cosign/sigstore dependency. It lets dsecrat verify signatures it
// did not itself produce, which the keyed path could not.

// Fulcio records the OIDC issuer in a certificate extension. The v1 OID carries
// the issuer as a bare UTF8 string; the v2 OID wraps it in a DER UTF8String.
var (
	oidFulcioIssuerV1 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}
	oidFulcioIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// CosignIdentity is the signer identity extracted from a Fulcio certificate.
type CosignIdentity struct {
	// SubjectID is the SAN identity: an email, a SPIFFE ID, or a URI (e.g. a
	// GitHub Actions workflow ref). It is what a policy's certificate-identity is
	// matched against.
	SubjectID string
	// Issuer is the OIDC issuer URL from the Fulcio extension (e.g.
	// "https://token.actions.githubusercontent.com").
	Issuer string
	// NotBefore/NotAfter are the certificate's validity window.
	NotBefore, NotAfter time.Time
}

// CosignPolicy constrains which keyless identities are acceptable. An empty
// policy accepts any identity that chains to the trusted roots — callers should
// almost always set at least CertificateIdentity + CertificateOIDCIssuer, since
// a valid-but-unexpected signer is exactly the attack keyless signing invites.
type CosignPolicy struct {
	// CertificateIdentity, if set, must equal the certificate SAN identity, or —
	// when it ends with "*" — be a prefix match (for workflow-ref families).
	CertificateIdentity string
	// CertificateOIDCIssuer, if set, must equal the certificate's OIDC issuer.
	CertificateOIDCIssuer string
}

// CosignVerifier verifies keyless cosign signatures against a set of trusted
// Fulcio CA certificates.
type CosignVerifier struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
}

// NewCosignVerifier builds a verifier trusting the given Fulcio root CA
// certificate(s), supplied as PEM. Intermediates, if any, may be included in the
// same PEM bundle.
func NewCosignVerifier(rootPEM []byte) (*CosignVerifier, error) {
	roots := x509.NewCertPool()
	intermediates := x509.NewCertPool()
	rest := rootPEM
	n := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("cosign trust root: parse certificate: %w", err)
		}
		if cert.IsCA && cert.CheckSignatureFrom(cert) == nil {
			roots.AddCert(cert) // self-signed → root
		} else {
			intermediates.AddCert(cert)
			roots.AddCert(cert) // also trust as an anchor if the bundle is intermediate-only
		}
		n++
	}
	if n == 0 {
		return nil, errors.New("cosign trust root: no certificates found in PEM")
	}
	return &CosignVerifier{roots: roots, intermediates: intermediates}, nil
}

// VerifyImageSignature verifies a keyless signature over a simple-signing
// payload: it validates the certificate chain (as of signingTime), enforces the
// identity policy, and checks the signature under the certificate's public key.
// It returns the extracted identity on success.
//
// certPEM is the signing certificate (Fulcio leaf); payload is the raw
// simple-signing JSON; signature is the raw signature bytes cosign produced over
// that payload. signingTime is when the signature was made (from the Rekor entry
// or the certificate's NotBefore when unknown).
func (v *CosignVerifier) VerifyImageSignature(certPEM, payload, signature []byte, pol CosignPolicy, signingTime time.Time) (*CosignIdentity, error) {
	leaf, err := parseLeaf(certPEM)
	if err != nil {
		return nil, err
	}

	if signingTime.IsZero() {
		signingTime = leaf.NotBefore
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: v.intermediates,
		CurrentTime:   signingTime,
		// Fulcio leaves are code-signing certs; accept any EKU so we do not reject
		// on EKU nuances across Fulcio versions. Identity policy is the real gate.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("%w: certificate chain: %v", ErrUntrusted, err)
	}

	id := identityFromCert(leaf)
	if err := pol.check(id); err != nil {
		return nil, err
	}

	ver, err := VerifierFromPublicKey(leaf.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("cosign: unsupported certificate key: %w", err)
	}
	if err := ver.Verify(payload, signature); err != nil {
		return nil, fmt.Errorf("%w: signature does not verify under the certificate key: %v", ErrVerify, err)
	}
	return id, nil
}

// check enforces the identity policy against an extracted identity.
func (p CosignPolicy) check(id *CosignIdentity) error {
	if p.CertificateOIDCIssuer != "" && !strings.EqualFold(p.CertificateOIDCIssuer, id.Issuer) {
		return fmt.Errorf("%w: issuer %q != required %q", ErrPolicy, id.Issuer, p.CertificateOIDCIssuer)
	}
	if want := p.CertificateIdentity; want != "" {
		if strings.HasSuffix(want, "*") {
			if !strings.HasPrefix(id.SubjectID, strings.TrimSuffix(want, "*")) {
				return fmt.Errorf("%w: identity %q does not match prefix %q", ErrPolicy, id.SubjectID, want)
			}
		} else if id.SubjectID != want {
			return fmt.Errorf("%w: identity %q != required %q", ErrPolicy, id.SubjectID, want)
		}
	}
	return nil
}

// parseLeaf decodes the first CERTIFICATE PEM block.
func parseLeaf(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("cosign: signing certificate is not valid PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cosign: parse signing certificate: %w", err)
	}
	return leaf, nil
}

// identityFromCert extracts the SAN identity and OIDC issuer from a Fulcio leaf.
func identityFromCert(c *x509.Certificate) *CosignIdentity {
	id := &CosignIdentity{NotBefore: c.NotBefore, NotAfter: c.NotAfter}
	switch {
	case len(c.EmailAddresses) > 0:
		id.SubjectID = c.EmailAddresses[0]
	case len(c.URIs) > 0:
		id.SubjectID = c.URIs[0].String()
	}
	for _, ext := range c.Extensions {
		switch {
		case ext.Id.Equal(oidFulcioIssuerV1):
			id.Issuer = string(ext.Value)
		case ext.Id.Equal(oidFulcioIssuerV2):
			var s string
			if _, err := asn1.Unmarshal(ext.Value, &s); err == nil && s != "" {
				id.Issuer = s
			} else {
				id.Issuer = string(ext.Value)
			}
		}
	}
	return id
}

// VerifyRekorInclusion verifies that the signature envelope was recorded in a
// Rekor-style transparency log, reusing the Merkle inclusion primitive. It binds
// the cosign path to the same tamper-evident-log guarantee the keyed path has.
// logVerifier is the log's public key verifier (its checkpoint signer).
func VerifyRekorInclusion(rec *InclusionRecord, loggedBytes []byte, logVerifier Verifier) error {
	return VerifyInclusion(rec, loggedBytes, logVerifier)
}
