package verify

import (
	"fmt"
	"os"

	"github.com/Ratnadeepdeyroy/docker-security/internal/registry"
	"github.com/Ratnadeepdeyroy/docker-security/internal/sig"
)

// --- Shared command helpers -------------------------------------------------
//
// These back the dsecrat sign|attest|verify subcommands. They favor clear errors
// over cleverness: a CLI that silently does the wrong thing with keys is worse
// than one that refuses and explains.

// loadOrGenerateKey loads a signer from keyPath, or — when keyPath is empty and
// genAlg is set — generates a fresh key and writes it to keyOut. Returns the
// signer. Generating uses crypto/rand (a CLI action, not analysis logic, so
// non-determinism is fine and desirable here).
func loadOrGenerateKey(keyPath, genAlg, keyOut, pubOut string) (sig.Signer, error) {
	if keyPath != "" {
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read key: %w", err)
		}
		return sig.LoadSignerPEM(data)
	}
	if genAlg == "" {
		return nil, fmt.Errorf("no --key provided and no --new-key algorithm requested")
	}
	signer, err := sig.GenerateKey(sig.Algorithm(genAlg), nil)
	if err != nil {
		return nil, err
	}
	if keyOut != "" {
		privPEM, err := sig.MarshalPrivateKeyPEM(signer)
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyOut, privPEM, 0o600); err != nil {
			return nil, fmt.Errorf("write generated key: %w", err)
		}
	}
	if pubOut != "" {
		pubPEM, err := sig.MarshalPublicKeyPEM(signer.Verifier())
		if err != nil {
			return nil, err
		}
		if err := os.WriteFile(pubOut, pubPEM, 0o644); err != nil {
			return nil, fmt.Errorf("write public key: %w", err)
		}
	}
	return signer, nil
}

// resolveDigest turns --digest / --image flags into a manifest digest. An
// explicit digest wins; otherwise the digest is read from an OCI layout dir.
func resolveDigest(digest, imagePath string) (string, error) {
	if digest != "" {
		if err := sig.ValidateDigest(digest); err != nil {
			return "", err
		}
		return digest, nil
	}
	if imagePath != "" {
		return registry.ManifestDigestFromLayout(imagePath)
	}
	return "", fmt.Errorf("provide --digest or --image")
}

// loadOrNewBundle opens an existing bundle at path (so attestations can be
// appended to a signature bundle) or creates a fresh one for the digest. It
// refuses to mix subjects: appending to a bundle for a different digest is a
// mistake worth stopping.
func loadOrNewBundle(path, digest string) (*sig.Bundle, error) {
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			b, err := sig.ParseBundle(data)
			if err != nil {
				return nil, err
			}
			if b.SubjectDigest != digest {
				return nil, fmt.Errorf("existing bundle targets %s, not %s; use a fresh --bundle-out", b.SubjectDigest, digest)
			}
			return b, nil
		}
	}
	return sig.NewBundle(digest)
}

// writeBundle marshals and writes a bundle to path (or stdout when path is "-").
func writeBundle(b *sig.Bundle, path string) error {
	data, err := b.Marshal()
	if err != nil {
		return err
	}
	if path == "" || path == "-" {
		_, err := os.Stdout.Write(append(data, '\n'))
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// maybeLog appends the marshaled envelope to a transparency log (if one is
// provided) and returns the inclusion record.
func maybeLog(log *sig.TransLog, env *sig.Envelope) (*sig.InclusionRecord, error) {
	if log == nil {
		return nil, nil
	}
	data, err := env.Marshal()
	if err != nil {
		return nil, err
	}
	return log.Append(data)
}
