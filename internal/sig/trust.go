package sig

import (
	"encoding/json"
	"fmt"
	"sort"
)

// --- Trust root & policy ----------------------------------------------------
//
// Cryptographic validity is necessary but never sufficient: an attacker can
// present a perfectly valid signature made by a key you have never trusted. The
// TrustRoot answers "is this key one we accept, and whose is it?", and Policy
// answers "is that a signer we allow for *this* artifact?". Verification that
// skips either step is the classic supply-chain bypass, so the API makes both
// explicit and fails closed when the trust root is empty.

// TrustedKey binds a verifier to an identity and issuer, mirroring the
// subject/issuer a keyless (Fulcio) certificate would carry. In a keyed
// deployment these are administrator-assigned labels ("ci@corp.example",
// "https://accounts.google.com"); in a keyless one they come from the cert SAN.
type TrustedKey struct {
	Verifier Verifier
	// Identity is the signer identity (email, SPIFFE ID, or builder URI).
	Identity string
	// Issuer is the OIDC issuer or CA that vouches for the identity, if any.
	Issuer string
}

// TrustRoot is the set of keys a verifier will accept, indexed by key ID.
type TrustRoot struct {
	keys map[string]TrustedKey
}

// NewTrustRoot returns an empty trust root. An empty root verifies nothing —
// that is the safe default, not a bug.
func NewTrustRoot() *TrustRoot { return &TrustRoot{keys: map[string]TrustedKey{}} }

// Add registers a trusted key. A later Add for the same key ID replaces the
// earlier binding.
func (t *TrustRoot) Add(k TrustedKey) error {
	if k.Verifier == nil {
		return fmt.Errorf("trust root: nil verifier")
	}
	t.keys[k.Verifier.KeyID()] = k
	return nil
}

// AddVerifier is a convenience for keys with no identity metadata.
func (t *TrustRoot) AddVerifier(v Verifier, identity string) error {
	return t.Add(TrustedKey{Verifier: v, Identity: identity})
}

// Len reports how many keys the trust root holds.
func (t *TrustRoot) Len() int { return len(t.keys) }

// KeyIDs returns the trusted key IDs in sorted order (for stable reporting).
func (t *TrustRoot) KeyIDs() []string {
	out := make([]string, 0, len(t.keys))
	for id := range t.keys {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Policy constrains which trusted signers are acceptable for a given artifact.
// A zero Policy (no identities, no issuers) accepts any key in the trust root —
// "trusted key" is itself the floor. Naming identities or issuers tightens it.
type Policy struct {
	// Identities, if non-empty, is the allow-list of acceptable signer
	// identities. A signer whose identity is not listed fails ErrPolicy.
	Identities []string
	// Issuers, if non-empty, is the allow-list of acceptable OIDC issuers/CAs.
	Issuers []string
}

// VerifyResult reports the outcome of a successful trust-root verification.
type VerifyResult struct {
	// KeyID is the trusted key that verified the envelope.
	KeyID string
	// Identity and Issuer are the labels bound to that key.
	Identity string
	Issuer   string
}

// Verify checks a DSSE envelope against the trust root and policy. It returns
// the identity of the first trusted key that both verifies a signature and
// satisfies the policy. Failure modes are distinct and wrapped:
//
//   - ErrUntrusted: a signature verified, but under no trusted key (or there
//     were no signatures a trusted key could check).
//   - ErrPolicy:    a trusted key verified, but its identity/issuer is not
//     allowed by the policy.
//
// The scan of trusted keys is order-independent (map iteration) but the outcome
// is not: a policy-satisfying match wins over a mere trusted match, so a
// multi-signer envelope is accepted as soon as one signer clears policy.
func (t *TrustRoot) Verify(env *Envelope, policy Policy) (VerifyResult, error) {
	if len(t.keys) == 0 {
		return VerifyResult{}, fmt.Errorf("empty trust root: %w", ErrUntrusted)
	}
	var trustedButBlocked bool
	for _, tk := range t.keys {
		if err := env.VerifyWith(tk.Verifier); err != nil {
			continue
		}
		// Cryptographically trusted. Now apply policy.
		if policy.allows(tk) {
			return VerifyResult{KeyID: tk.Verifier.KeyID(), Identity: tk.Identity, Issuer: tk.Issuer}, nil
		}
		trustedButBlocked = true
	}
	if trustedButBlocked {
		return VerifyResult{}, fmt.Errorf("signer not in policy allow-list: %w", ErrPolicy)
	}
	return VerifyResult{}, ErrUntrusted
}

// allows reports whether a trusted key satisfies the policy.
func (p Policy) allows(tk TrustedKey) bool {
	if len(p.Identities) > 0 && !contains(p.Identities, tk.Identity) {
		return false
	}
	if len(p.Issuers) > 0 && !contains(p.Issuers, tk.Issuer) {
		return false
	}
	return true
}

func contains(set []string, want string) bool {
	for _, s := range set {
		if s == want {
			return true
		}
	}
	return false
}

// --- Serializable trust configuration --------------------------------------

// TrustConfig is the on-disk form of a trust root: PEM public keys with their
// identities. It is what an operator commits to a repo or hands the verify
// module, so trust is reviewable configuration rather than code.
type TrustConfig struct {
	Keys   []TrustConfigKey `json:"keys"`
	Policy PolicyConfig     `json:"policy,omitempty"`
}

// TrustConfigKey is one entry in a TrustConfig.
type TrustConfigKey struct {
	// PublicKeyPEM is a PKIX PEM public key.
	PublicKeyPEM string `json:"public_key_pem"`
	Identity     string `json:"identity,omitempty"`
	Issuer       string `json:"issuer,omitempty"`
}

// PolicyConfig is the on-disk form of a Policy.
type PolicyConfig struct {
	Identities []string `json:"identities,omitempty"`
	Issuers    []string `json:"issuers,omitempty"`
}

// LoadTrustConfig parses a JSON TrustConfig into a TrustRoot and Policy.
func LoadTrustConfig(data []byte) (*TrustRoot, Policy, error) {
	var cfg TrustConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, Policy{}, fmt.Errorf("parse trust config: %w", err)
	}
	return cfg.Build()
}

// Build materializes a TrustConfig into a TrustRoot and Policy. It is the shared
// core of LoadTrustConfig and of callers (the verify module) that already hold a
// decoded config.
func (cfg TrustConfig) Build() (*TrustRoot, Policy, error) {
	tr := NewTrustRoot()
	for i, k := range cfg.Keys {
		v, err := LoadVerifierPEM([]byte(k.PublicKeyPEM))
		if err != nil {
			return nil, Policy{}, fmt.Errorf("trust config key %d: %w", i, err)
		}
		if err := tr.Add(TrustedKey{Verifier: v, Identity: k.Identity, Issuer: k.Issuer}); err != nil {
			return nil, Policy{}, err
		}
	}
	pol := Policy{Identities: cfg.Policy.Identities, Issuers: cfg.Policy.Issuers}
	return tr, pol, nil
}
