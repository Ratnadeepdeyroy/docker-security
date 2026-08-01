package verify

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/sig"
)

// verifyCosignCommand implements `dsecrat verify cosign`: keyless (Fulcio)
// signature verification against a trusted Fulcio root, enforcing the expected
// certificate identity and OIDC issuer. This lets dsecrat verify signatures made by
// cosign in the wild, which the keyed bundle path cannot.
//
//	dsecrat verify cosign \
//	  --root fulcio-root.pem --cert leaf.pem \
//	  --payload payload.json --signature sig.bin \
//	  --certificate-identity https://github.com/acme/app/... \
//	  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
//	  [--digest sha256:...]
func verifyCosignCommand(args []string) int {
	fs := flag.NewFlagSet("verify cosign", flag.ContinueOnError)
	rootPath := fs.String("root", "", "trusted Fulcio root CA certificate (PEM); required")
	certPath := fs.String("cert", "", "signing certificate to verify (PEM); required")
	payloadPath := fs.String("payload", "", "signed simple-signing payload (JSON); required")
	sigPath := fs.String("signature", "", "raw signature bytes over the payload; required")
	identity := fs.String("certificate-identity", "", "required SAN identity (exact, or a trailing * for prefix match)")
	issuer := fs.String("certificate-oidc-issuer", "", "required OIDC issuer URL")
	digest := fs.String("digest", "", "expected image manifest digest (sha256:...) the payload must commit to")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	for name, val := range map[string]string{"--root": *rootPath, "--cert": *certPath, "--payload": *payloadPath, "--signature": *sigPath} {
		if val == "" {
			return fail("verify cosign", fmt.Errorf("%s is required", name))
		}
	}

	rootPEM, err := os.ReadFile(*rootPath)
	if err != nil {
		return fail("verify cosign", err)
	}
	certPEM, err := os.ReadFile(*certPath)
	if err != nil {
		return fail("verify cosign", err)
	}
	payload, err := os.ReadFile(*payloadPath)
	if err != nil {
		return fail("verify cosign", err)
	}
	signature, err := os.ReadFile(*sigPath)
	if err != nil {
		return fail("verify cosign", err)
	}

	v, err := sig.NewCosignVerifier(rootPEM)
	if err != nil {
		return fail("verify cosign", err)
	}
	pol := sig.CosignPolicy{CertificateIdentity: *identity, CertificateOIDCIssuer: *issuer}

	// signingTime is unknown without a Rekor entry; NewCosignVerifier falls back
	// to the certificate NotBefore, which is correct for short-lived Fulcio certs.
	id, err := v.VerifyImageSignature(certPEM, payload, signature, pol, time.Time{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify cosign: verdict FAILED: %v\n", err)
		return 1
	}

	// Optional digest binding: the payload must commit to the expected image.
	if *digest != "" {
		parsed, perr := sig.ParseImagePayload(payload)
		if perr != nil {
			return fail("verify cosign", perr)
		}
		if parsed.SignedDigest() != *digest {
			fmt.Fprintf(os.Stderr, "verify cosign: verdict FAILED: payload commits to %s, not %s\n", parsed.SignedDigest(), *digest)
			return 1
		}
	}

	fmt.Fprintf(os.Stderr, "verify cosign: verdict PASSED\n  identity: %s\n  issuer:   %s\n", id.SubjectID, id.Issuer)
	return 0
}
