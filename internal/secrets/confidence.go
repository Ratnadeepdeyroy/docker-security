// internal/secrets/confidence.go
package secrets

import (
	"bytes"
	"strings"
)

// --- Confidence grading -------------------------------------------------------
//
// Corroboration model: a detection is more trustworthy when independent signals
// agree on it. The formulas and this implementation are ours. Confidence is
// advisory metadata layered on top of
// the existing scan — it never changes whether something is reported, only
// how strongly an agent or reviewer should weight it.

// contextWindowRadius bounds how far around a hit offset we look for
// corroborating provider-name mentions (e.g. "github.com" near a token).
// 128 bytes on each side gives ~256 bytes total, enough to cover the current
// line and its immediate neighbors without pulling in unrelated content.
const contextWindowRadius = 128

// contextWindow returns the up-to-256-byte slice of data anchored on offset
// (offset-128 .. offset+128), clamped to data's bounds. offset is the start
// of the matched value, not its center or midpoint, so for a long value the
// window is not symmetric around the hit as a whole — up to contextWindowRadius
// bytes before the value and up to contextWindowRadius bytes after its start
// are covered, which for values near the length ceiling can exclude some
// trailing context after the value's own end. It never allocates a copy
// beyond what slicing already shares, and it never includes the secret's own
// bytes beyond what naturally falls in the window — confidenceFor only ever
// inspects this window for keyword hints, never the secret value itself.
func contextWindow(data []byte, offset int) []byte {
	if offset < 0 {
		offset = 0
	}
	if offset > len(data) {
		offset = len(data)
	}
	start := offset - contextWindowRadius
	if start < 0 {
		start = 0
	}
	end := offset + contextWindowRadius
	if end > len(data) {
		end = len(data)
	}
	return data[start:end]
}

// providerHints maps a detection slug prefix to lowercase context words whose
// presence near the hit corroborates it (the named provider is actually in
// use, not just a coincidentally-shaped string). Prefixes are verified
// against the real slugs in rules.go — see the comment on confidenceFor for
// why an unmatched provider hit is graded "medium" rather than promoted on
// shape alone.
var providerHints = map[string][]string{
	"aws":          {"aws", "amazon"},
	"gcp":          {"gcp", "google", "firebase"},
	"google":       {"google", "gcp", "firebase"},
	"github":       {"github"},
	"gitlab":       {"gitlab"},
	"slack":        {"slack"},
	"stripe":       {"stripe"},
	"openai":       {"openai"},
	"anthropic":    {"anthropic", "claude"},
	"twilio":       {"twilio"},
	"shopify":      {"shopify"},
	"sendgrid":     {"sendgrid"},
	"mailgun":      {"mailgun"},
	"mailchimp":    {"mailchimp"},
	"telegram":     {"telegram"},
	"discord":      {"discord"},
	"postman":      {"postman"},
	"airtable":     {"airtable"},
	"figma":        {"figma"},
	"grafana":      {"grafana"},
	"sentry":       {"sentry"},
	"mapbox":       {"mapbox"},
	"square":       {"square"},
	"pypi":         {"pypi", "twine"},
	"rubygems":     {"rubygems", "gem"},
	"dockerhub":    {"dockerhub", "docker"},
	"hashicorp":    {"vault", "hashicorp"},
	"huggingface":  {"huggingface", "hf.co"},
	"digitalocean": {"digitalocean"},
	"npm":          {"npm", "registry.npmjs.org"},
}

// minGenericConfidenceEntropy and minGenericConfidenceLength are the
// scoring-only thresholds that promote a generic (keyword/entropy-heuristic)
// hit from "low" to "medium" confidence. These are independent of, and
// deliberately looser than, the gating thresholds in generic.go
// (minAssignEntropy, minBareEntropy) — a detection has already cleared those
// to exist at all; these two only grade how strongly to trust it.
//
// 3.6 (rather than a round 4.0) is deliberate: averageEntropy's three-way
// blend (see entropy.go) tops out at exactly log2(k) for a perfectly uniform
// k-symbol alphabet, so a 16-symbol hex secret maxes out at 4.0 — but real
// random samples of finite length almost never land exactly on that ceiling
// (sampling variance pulls the observed distribution slightly off-uniform).
// 3.6 leaves enough margin that a genuinely high-randomness hex secret
// (len >= minGenericConfidenceLength) can clear the bar in practice, not just
// in the theoretical limit, while still sitting well above prose/word-shaped
// values (e.g. "password" scores ~2.5).
const (
	minGenericConfidenceEntropy = 3.6
	minGenericConfidenceLength  = 24
)

// confidenceFor grades a Detection's corroboration level.
//
// Provider-rule hits (a recognizable, anchored credential shape — AWS,
// GitHub, ...) start at "medium": the shape alone is a real signal, but shape
// can coincide with test fixtures, documentation examples, and rotated/dead
// keys still sitting in a repo. They are promoted to "high" only when the
// provider's name is actually mentioned in the surrounding bytes — independent
// corroboration that the provider is genuinely in use here, not just a string
// that happens to match
// the shape. Deliberately NOT promoted on length/shape alone: that would
// make nearly every real provider token "high" regardless of context, which
// defeats the point of a confidence grade.
//
// Generic hits (keyword-assignment or bare-entropy heuristics, KindGeneric,
// and honeytoken canaries, KindCanary) carry no distinctive shape to lean on,
// so they start at "low" and are promoted to "medium" only by strong
// multi-entropy (secret's averageEntropy, not the Shannon-only Detection.Entropy
// field) plus length — never "high", since nothing here corroborates them
// against a real provider.
func confidenceFor(d Detection, secret string, context []byte) string {
	if d.Kind == KindGeneric || d.Kind == KindCanary {
		if averageEntropy(secret) >= minGenericConfidenceEntropy && d.Length >= minGenericConfidenceLength {
			return "medium"
		}
		return "low"
	}

	lower := bytes.ToLower(context)
	for prefix, hints := range providerHints {
		if !strings.HasPrefix(d.Slug, prefix) {
			continue
		}
		for _, h := range hints {
			if bytes.Contains(lower, []byte(h)) {
				return "high"
			}
		}
	}
	return "medium"
}
