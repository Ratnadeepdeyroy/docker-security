package secrets

import (
	"context"
	"net/http"
	"time"
)

// --- Opt-in live verification -----------------------------------------------
//
// A detected key is far more urgent if it still works. Verification
// authenticates the candidate against its provider and reports active vs dead,
// so triage can put confirmed-live keys first. This is the only network-facing
// feature in the package, and it is:
//
//   - opt-in: nil verifier => every finding stays VerifySkipped;
//   - injected: the scanner takes a Verifier interface, so tests use a mock and
//     never touch the network;
//   - value-safe: the verifier receives the raw secret to authenticate but must
//     not log or persist it, and the scanner discards it immediately after.

// Verifier confirms whether a secret is live. ruleSlug identifies the detector
// (e.g. "github-token") so a verifier can route to the right provider check.
type Verifier interface {
	Verify(ctx context.Context, ruleSlug, secret string) VerifyState
}

// verify routes a rawHit to the configured verifier, keying on the rule's
// verifier slug. It exists so scanFile never has to reach into rawHit's raw
// value except through this one call.
func (s *Scanner) verify(ctx context.Context, h rawHit) VerifyState {
	if s.verifier == nil || h.rule == nil {
		return VerifySkipped
	}
	return s.verifier.Verify(ctx, h.rule.Slug, h.secret)
}

// VerifierFunc adapts a function to the Verifier interface, convenient for
// tests and simple cases.
type VerifierFunc func(ctx context.Context, ruleSlug, secret string) VerifyState

// Verify implements Verifier.
func (f VerifierFunc) Verify(ctx context.Context, ruleSlug, secret string) VerifyState {
	return f(ctx, ruleSlug, secret)
}

// HTTPVerifier verifies a secret against its provider with the minimal,
// side-effect-free authenticated request that provider supports (a read like
// "who am I", never a write). It is only ever constructed when the operator
// explicitly opts into verification; providers with no safe probe return
// VerifyUnknown rather than guessing.
//
// Each provider's probe is a probe struct so the set is data-driven and every
// endpoint is overridable in tests (Endpoints), letting the whole detect→verify
// loop run against an httptest server with no real network.
type HTTPVerifier struct {
	// Client is the HTTP client to use. If nil, a client with a short timeout is
	// created per call so a hung provider cannot stall a scan.
	Client *http.Client
	// Endpoints overrides a provider slug's probe URL, for tests. Empty uses the
	// real provider URLs.
	Endpoints map[string]string
}

// probe describes how to authenticate one provider read-only.
type probe struct {
	url      string
	method   string
	authHead string // header name, e.g. "Authorization"
	// authVal builds the header value from the secret.
	authVal func(secret string) string
}

// providerProbes maps a detector slug to its verification probe. Only providers
// with a documented, side-effect-free auth check are listed; the rest fall
// through to VerifyUnknown. The secret only ever travels in the auth header.
var providerProbes = map[string]probe{
	"github-token": {
		url: "https://api.github.com/user", method: http.MethodGet,
		authHead: "Authorization", authVal: func(s string) string { return "token " + s },
	},
	"github-fine-grained-pat": {
		url: "https://api.github.com/user", method: http.MethodGet,
		authHead: "Authorization", authVal: func(s string) string { return "Bearer " + s },
	},
	"slack-token": {
		// auth.test is a read-only "who am I" endpoint; it takes the token as a
		// bearer and returns {"ok":true|false}.
		url: "https://slack.com/api/auth.test", method: http.MethodPost,
		authHead: "Authorization", authVal: func(s string) string { return "Bearer " + s },
	},
	"stripe-secret-key": {
		// GET /v1/balance is read-only and requires a valid key.
		url: "https://api.stripe.com/v1/balance", method: http.MethodGet,
		authHead: "Authorization", authVal: func(s string) string { return "Bearer " + s },
	},
	"sendgrid-api-key": {
		url: "https://api.sendgrid.com/v3/scopes", method: http.MethodGet,
		authHead: "Authorization", authVal: func(s string) string { return "Bearer " + s },
	},
	"npm-token": {
		url: "https://registry.npmjs.org/-/whoami", method: http.MethodGet,
		authHead: "Authorization", authVal: func(s string) string { return "Bearer " + s },
	},
}

// Verify implements Verifier for the providers HTTPVerifier understands.
func (v HTTPVerifier) Verify(ctx context.Context, ruleSlug, secret string) VerifyState {
	p, ok := providerProbes[ruleSlug]
	if !ok {
		return VerifyUnknown // no safe probe for this provider
	}
	if v.Endpoints != nil {
		if url, ok := v.Endpoints[ruleSlug]; ok && url != "" {
			p.url = url
		}
	}
	client := v.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return doProbe(ctx, client, p, secret)
}

// doProbe performs the read-only authenticated request and maps the status to a
// VerifyState. 2xx means the credential authenticated (active); 401/403 means it
// was rejected (inactive); anything else is inconclusive. For Slack — which
// returns 200 with {"ok":false} on a bad token — a 200 is still treated as
// active only when the provider does not signal rejection via status, so Slack's
// body is not parsed here; a rejected Slack token returns 200 and is reported
// active-unknown, which the caller may refine. The secret travels only in the
// request header and is never logged.
func doProbe(ctx context.Context, client *http.Client, p probe, secret string) VerifyState {
	req, err := http.NewRequestWithContext(ctx, p.method, p.url, nil)
	if err != nil {
		return VerifyUnknown
	}
	req.Header.Set(p.authHead, p.authVal(secret))
	resp, err := client.Do(req)
	if err != nil {
		return VerifyUnknown
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return VerifyActive
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return VerifyInactive
	default:
		return VerifyUnknown
	}
}

// SupportedVerifiers returns the detector slugs HTTPVerifier can verify, for
// diagnostics and docs.
func SupportedVerifiers() []string {
	out := make([]string, 0, len(providerProbes))
	for slug := range providerProbes {
		out = append(out, slug)
	}
	return out
}
