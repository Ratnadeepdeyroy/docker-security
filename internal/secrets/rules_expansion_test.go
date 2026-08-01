package secrets

import (
	"strings"
	"testing"
)

// Every case: a synthetic token matching the documented public shape, and the
// rule that must catch it. Values are fabricated, not real credentials.
func TestExpandedProviderRules(t *testing.T) {
	cases := []struct {
		slug string
		text string
	}{
		{"gitlab-pat", "token: glpat-AbC" + "dEfGhIjKlMnOpQrSt"},
		{"gitlab-pipeline-trigger", "glptt-0123456789abcdef0" + "123456789abcdef01234567"},
		{"digitalocean-token", "dop_v1_" + strings.Repeat("a1", 32)},
		{"openai-api-key", "sk-proj-AbCdEfGhIjKlMnOpQrSt" + "T3BlbkFJAbCdEfGhIjKlMnOpQrSt"},
		{"anthropic-api-key", "sk-ant-api03-" + strings.Repeat("a", 93) + "AA"},
		{"huggingface-token", "hf_AbCdEfGhIjKlMnO" + "pQrStUvWxYzAbCdEfGh"},
		{"shopify-access-token", "shpat_0123456789abc" + "def0123456789abcdef"},
		{"shopify-shared-secret", "shpss_0123456789abc" + "def0123456789abcdef"},
		{"twilio-api-key", "twilio_auth: SK01234567" + "89abcdef0123456789abcdef"},
		{"hashicorp-vault-token", "hvs.AbCdEfGhIj" + "KlMnOpQrStUvWx"},
		{"telegram-bot-token", "110201543:AAHdqTcvCH1v" + "GWJxfSeofSAs0K5PALDsaw"},
		{"discord-webhook", "https://discord.com/api/webhooks/1234567890/A" + "bCdEf_GhIjKlMnOpQrStUvWxYz-1234567890AbCdEfGh"},
		{"pypi-token", "pypi-AgEIcHlwaS5vcmc" + strings.Repeat("A", 60)},
		{"rubygems-key", "rubygems_0123456789abcdef012" + "3456789abcdef0123456789abcdef"},
		{"square-access-token", "sq0atp-AbCdEfG" + "hIjKlMnOpQrStUv"},
		{"mailgun-key", "mailgun_api_key = key-01234" + "56789abcdef0123456789abcdef"},
		{"mailchimp-key", "0123456789abcdef01" + "23456789abcdef-us12"},
		{"grafana-service-account", "glsa_AbCdEfGhIjKlMnOpQr" + "StUvWxYz012345_0a1b2c3d"},
		{"postman-api-key", "PMAK-0123456789abcdef01234567-01" + "23456789abcdef0123456789abcdef01"},
		{"airtable-pat", "patAbCdEfGhIjKlMn.0123456789abcdef0123456" + "789abcdef0123456789abcdef0123456789abcdef"},
		{"figma-pat", "figd_AbCdEfGhIjKlMnOpQ" + "rStUvWxYz0123456789AbCd"},
		{"dockerhub-pat", "dckr_pat_AbCdEfGhI" + "jKlMnOpQrStUvWxYz1"},
		{"sentry-dsn", "https://0123456789abcdef0123456789abcdef:fedcba9876" + "543210fedcba9876543210@o123456.ingest.sentry.io/4505"},
		{"mapbox-secret-token", "sk.eyJ1IjoiZm9vIiwiYSI6ImJh" + "ciJ9.0123456789AbCdEfGhIjKl"},
	}
	for _, c := range cases {
		hits := applyProviderRules([]byte(c.text), false)
		found := false
		for _, h := range hits {
			if h.rule.Slug == c.slug {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: not detected in %q", c.slug, c.text)
		}
	}
}

// A few realistic non-secret strings must not be caught by any of the newly
// added provider rules: a git commit SHA, a UUID, and a base64 image chunk.
func TestExpandedProviderRulesNoFalsePositives(t *testing.T) {
	newSlugs := map[string]bool{
		"gitlab-pat": true, "gitlab-pipeline-trigger": true, "digitalocean-token": true,
		"openai-api-key": true, "anthropic-api-key": true, "huggingface-token": true,
		"shopify-access-token": true, "shopify-shared-secret": true, "twilio-api-key": true,
		"hashicorp-vault-token": true, "telegram-bot-token": true, "discord-webhook": true,
		"pypi-token": true, "rubygems-key": true, "square-access-token": true,
		"mailgun-key": true, "mailchimp-key": true, "grafana-service-account": true,
		"postman-api-key": true, "airtable-pat": true, "figma-pat": true,
		"dockerhub-pat": true, "sentry-dsn": true, "mapbox-secret-token": true,
	}
	benign := []string{
		"commit 4b825dc642cb6eb9a060e54bf8d69288fbee4904 fixed the build",
		"request-id: 550e8400-e29b-41d4-a716-446655440000",
		"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
		// Hex strings alone (no provider keyword) sit at ~4.0 Shannon entropy,
		// the same band as a genuine twilio-api-key or mailgun-key value. Both
		// rules must require the provider keyword, not just fire on shape+entropy.
		"cache-key-0123456789abcdef0123456789abcdef",
		"checksum: SK0011223344556677" + "8899aabbccddeeff",
		// The modern, single-key Sentry DSN is Sentry's own documented
		// safe-to-expose public config shape (no secret half after a colon) --
		// it must NOT match sentry-dsn, which is anchored to the deprecated
		// two-part `pubkey:secretkey@` legacy shape only.
		"https://0123456789abcdef0123456789abcdef@o123456.ingest.sentry.io/4505",
	}
	for _, text := range benign {
		hits := applyProviderRules([]byte(text), false)
		for _, h := range hits {
			if newSlugs[h.rule.Slug] {
				t.Errorf("benign string %q unexpectedly matched new rule %q", text, h.rule.Slug)
			}
		}
	}
}

// TestBoundedTokenQuantifiersCapOvercapture locks in the fix for a
// polish-lens finding: gitlab-pat/vault-token/pypi-token/figma-pat/
// dockerhub-pat used an unbounded `{N,}` quantifier over a charclass that
// includes `-`/`_`, so any adjacent dash/underscore-joined text sharing the
// same charset was swallowed into the captured "secret," corrupting its
// fingerprint/length. A real token followed by a long run of dash-joined
// filler (e.g. a trailing comment like `-do-not-rotate-me`) must now be
// captured only up to the provider's bounded max length, not the whole run.
func TestBoundedTokenQuantifiersCapOvercapture(t *testing.T) {
	longFiller := strings.Repeat("-filler", 30) // 210 chars of dash-joined text

	cases := []struct {
		slug      string
		prefix    string
		tokenBody string // the token's own random-looking body, within bounds
		maxRepeat int    // the rule's upper bound on the repeated charclass
	}{
		{"gitlab-pat", "glpat-", strings.Repeat("a", 20), 64},
		{"hashicorp-vault-token", "hvs.", strings.Repeat("a", 24), 64},
		{"figma-pat", "figd_", strings.Repeat("a", 40), 64},
		{"dockerhub-pat", "dckr_pat_", strings.Repeat("a", 27), 64},
		{"pypi-token", "pypi-AgEIcHlwaS5vcmc", strings.Repeat("A", 50), 200},
	}
	for _, c := range cases {
		text := c.prefix + c.tokenBody + longFiller
		hits := applyProviderRules([]byte(text), false)
		found := false
		for _, h := range hits {
			if h.rule.Slug != c.slug {
				continue
			}
			found = true
			// The bound caps the *maximum* captured length; it does not claim to
			// stop a shorter run of adjacent filler from being captured within
			// that bound (that would need a stricter charclass, a separate
			// concern from the unbounded-quantifier bug this test targets). What
			// it must guarantee is that the previously-unbounded `{N,}` can no
			// longer swallow an arbitrarily long tail.
			maxTotal := len(c.prefix) + c.maxRepeat
			if len(h.secret) > maxTotal {
				t.Errorf("%s: captured secret length %d exceeds the bounded max %d (over-capture): %q",
					c.slug, len(h.secret), maxTotal, h.secret)
			}
			if len(h.secret) >= len(text)-1 {
				t.Errorf("%s: captured secret swallowed nearly the entire input (unbounded-style over-capture): %q", c.slug, h.secret)
			}
		}
		if !found {
			t.Errorf("%s: not detected in %q", c.slug, text)
		}
	}
}

// TestDigitalOceanPrefixNarrowed locks in the fix for a polish-lens finding:
// the digitalocean-token charclass `do[pors]_v1_` included an undocumented
// 4th prefix (`dos_v1_`) that doesn't correspond to any real DigitalOcean
// token type (dop_/doo_/dor_ are the only documented v1 prefixes). A
// `dos_v1_...` string must no longer match.
func TestDigitalOceanPrefixNarrowed(t *testing.T) {
	bogus := "dos_v1_" + strings.Repeat("a1", 32)
	hits := applyProviderRules([]byte(bogus), false)
	for _, h := range hits {
		if h.rule.Slug == "digitalocean-token" {
			t.Errorf("bogus dos_v1_ prefix must not match digitalocean-token, got: %q", h.secret)
		}
	}
	// The three real prefixes must still match.
	for _, prefix := range []string{"dop_v1_", "doo_v1_", "dor_v1_"} {
		text := prefix + strings.Repeat("a1", 32)
		hits := applyProviderRules([]byte(text), false)
		found := false
		for _, h := range hits {
			if h.rule.Slug == "digitalocean-token" {
				found = true
			}
		}
		if !found {
			t.Errorf("real prefix %q must still match digitalocean-token", prefix)
		}
	}
}
