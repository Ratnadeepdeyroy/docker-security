// Package verify is the engine module and command surface for supply-chain
// verification. It answers, for an image, the question a deploy gate cares
// about: "is this signed by someone we trust, does it carry the attestations we
// require, and does every signature actually bind to *this* digest?" The heavy
// lifting lives in internal/sig (DSSE, trust, transparency log) and
// internal/attest (in-toto statements); this package resolves inputs, drives the
// verification, and projects the outcome into the unified Finding model with the
// DS-RAT-SUP- rule namespace.
//
// It fails closed. When no trust root is configured it does not pretend an image
// is fine — it reports that verification is not configured (INFO) and verifies
// nothing. When a trust root *is* present, an unsigned or unverifiable image is
// a finding, and a signature that binds to a different digest is treated as a
// tamper attempt (CRITICAL), never quietly ignored.
package verify

import (
	"encoding/json"
	"fmt"

	"github.com/Ratnadeepdeyroy/docker-security/internal/sig"
)

// Config is the operator-supplied verification policy. It is JSON so it can be
// committed and reviewed alongside the images it governs.
type Config struct {
	// Trust is the set of trusted signing keys and the signer policy.
	Trust sig.TrustConfig `json:"trust"`
	// LogPublicKeyPEM, if set, is the transparency-log public key used to verify
	// inclusion proofs carried in a bundle.
	LogPublicKeyPEM string `json:"log_public_key_pem,omitempty"`
	// RequireAttestations lists predicate type URIs that must each be present and
	// verified (e.g. an SBOM or SLSA provenance attestation). An image missing a
	// required attestation is a finding.
	RequireAttestations []string `json:"require_attestations,omitempty"`
	// RequireTransparencyLog demands a valid inclusion proof for each signature.
	RequireTransparencyLog bool `json:"require_transparency_log,omitempty"`
	// EnableAgentActions turns on processing of AI-agent-action attestations.
	// Off by default: the deterministic verify core never depends on it.
	EnableAgentActions bool `json:"enable_agent_actions,omitempty"`
}

// resolved holds the config turned into live verification objects.
type resolved struct {
	trust  *sig.TrustRoot
	policy sig.Policy
	logVer sig.Verifier // nil if no log key configured
	cfg    Config
}

// build materializes a Config. A config with no keys yields a usable but empty
// trust root (which then verifies nothing — the fail-closed default).
func (c Config) build() (*resolved, error) {
	tr, pol, err := c.Trust.Build()
	if err != nil {
		return nil, err
	}
	r := &resolved{trust: tr, policy: pol, cfg: c}
	if c.LogPublicKeyPEM != "" {
		v, err := sig.LoadVerifierPEM([]byte(c.LogPublicKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("load transparency-log key: %w", err)
		}
		r.logVer = v
	}
	return r, nil
}

// ParseConfig decodes a module Config from JSON.
func ParseConfig(data []byte) (Config, error) {
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("parse verify config: %w", err)
	}
	return c, nil
}
