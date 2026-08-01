// internal/secrets/confidence_test.go
package secrets

import (
	"strings"
	"testing"
)

func TestAverageEntropy(t *testing.T) {
	if e := averageEntropy("aaaaaaaa"); e > 0.01 {
		t.Fatalf("uniform string must have ~0 entropy, got %f", e)
	}
	lo := averageEntropy("password")
	hi := averageEntropy("x9$Kp2!mQz7&Wd4c")
	if hi <= lo {
		t.Fatalf("random-looking string must outscore a word: %f <= %f", hi, lo)
	}
}

func TestConfidence(t *testing.T) {
	// Provider rule + provider name in context => high.
	d := Detection{Slug: "github-token", Kind: KindVCS, Entropy: 4.5, Length: 40}
	secret := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	if c := confidenceFor(d, secret, []byte("GITHUB_TOKEN=ghp_xxx pushed to github.com")); c != "high" {
		t.Fatalf("want high, got %s", c)
	}
	// Generic hit, low entropy/length, no context => low.
	g := Detection{Slug: "generic-assigned-secret", Kind: KindGeneric, Entropy: 3.3, Length: 12}
	if c := confidenceFor(g, "something", []byte("val = something")); c != "low" {
		t.Fatalf("want low, got %s", c)
	}
}

// TestConfidenceProviderWithoutContextIsMedium locks in the deliberate design
// choice that a provider-shaped hit is never promoted on shape/length alone:
// without a corroborating provider-name mention nearby, it stays "medium",
// never "high".
func TestConfidenceProviderWithoutContextIsMedium(t *testing.T) {
	d := Detection{Slug: "github-token", Kind: KindVCS, Entropy: 4.5, Length: 40}
	secret := "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
	if c := confidenceFor(d, secret, []byte("some unrelated surrounding text with no provider name")); c != "medium" {
		t.Fatalf("provider hit without corroborating context should be medium, got %s", c)
	}
}

// TestConfidenceEveryProviderRule walks every entry in the real providerRules
// table (rules.go) and checks that confidenceFor grades it correctly: "high"
// when the provider's own name is mentioned nearby, "medium" otherwise. Rules
// with no provider-name hint registered (private keys, JWTs, DB URIs — not
// tied to a single named vendor) must always grade "medium", never "high".
func TestConfidenceEveryProviderRule(t *testing.T) {
	unrelatedContext := []byte("this is some ordinary surrounding text with nothing distinctive in it")

	for _, r := range providerRules {
		r := r
		if r.Kind == KindGeneric || r.Kind == KindCanary {
			// e.g. sentry-dsn is deliberately classified generic; covered by the
			// generic-confidence tests instead.
			continue
		}
		t.Run(r.Slug, func(t *testing.T) {
			d := Detection{Slug: r.Slug, Kind: r.Kind, Severity: r.Severity, Length: 32}

			hint, ok := hintFor(r.Slug)
			if !ok {
				// No provider-name hint registered for this slug: it can never be
				// promoted, regardless of context.
				if c := confidenceFor(d, "secretvalue", unrelatedContext); c != "medium" {
					t.Errorf("%s: no hint registered, want medium always, got %s", r.Slug, c)
				}
				return
			}

			// Corroborating context => high.
			ctx := []byte("we use " + hint + " in production, see the token below")
			if c := confidenceFor(d, "secretvalue", ctx); c != "high" {
				t.Errorf("%s: with hint %q in context, want high, got %s", r.Slug, hint, c)
			}
			// No corroborating context => medium, never high.
			if c := confidenceFor(d, "secretvalue", unrelatedContext); c != "medium" {
				t.Errorf("%s: without hint in context, want medium, got %s", r.Slug, c)
			}
		})
	}
}

// hintFor returns one registered hint word for slug's provider prefix, if any.
func hintFor(slug string) (string, bool) {
	for prefix, hints := range providerHints {
		if strings.HasPrefix(slug, prefix) && len(hints) > 0 {
			return hints[0], true
		}
	}
	return "", false
}

// TestConfidenceGenericLow covers generic (keyword/entropy heuristic) and
// canary detections that don't clear the entropy+length bar: always low.
func TestConfidenceGenericLow(t *testing.T) {
	cases := []struct {
		name   string
		d      Detection
		secret string
	}{
		{"low entropy short", Detection{Slug: "generic-assigned-secret", Kind: KindGeneric, Length: 8}, "password"},
		{"weak password", Detection{Slug: "weak-hardcoded-password", Kind: KindGeneric, Length: 9}, "hunter2!!"},
		{"canary", Detection{Slug: "honeytoken-canary", Kind: KindCanary, Length: 8}, "aaaaaaaa"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if c := confidenceFor(tc.d, tc.secret, nil); c != "low" {
				t.Errorf("%s: want low, got %s", tc.name, c)
			}
		})
	}
}

// TestConfidenceGenericMedium covers a generic hit whose secret is genuinely
// high-entropy and long enough: promoted to medium, but never to high (there
// is no provider to corroborate against).
func TestConfidenceGenericMedium(t *testing.T) {
	d := Detection{Slug: "high-entropy-string", Kind: KindGeneric, Length: 32}
	secret := "k7Jd9fLp2Qw8zXcV3bNm5tYr1sAe6uHi" // 32 chars, high entropy
	if c := confidenceFor(d, secret, nil); c != "medium" {
		t.Errorf("want medium, got %s", c)
	}
}

// TestConfidenceHexSecretCanReachMedium locks in the fix for the polish-lens
// finding that averageEntropy's old 4-term blend (Shannon + Rényi +
// min-entropy + 4*Tsallis) made "medium" confidence mathematically
// unreachable for ANY hex-alphabet secret: the formula's own maximum
// achievable value for a 16-symbol alphabet (3.9375) sat below the 4.0
// threshold, no matter how long or randomly generated the secret was. A
// long, high-randomness hex secret (a very common real shape: session
// tokens, hex-encoded API secrets, SECRET_KEY values) must be able to grade
// "medium", not be permanently capped at "low".
func TestConfidenceHexSecretCanReachMedium(t *testing.T) {
	// A realistic (not artificially perfectly-balanced) 32-char random hex
	// string — plausible output of any hex-encoding secret generator.
	hexSecret := "7f3ac9e01db4562fa8c9013dd57e2b6f"
	if len(hexSecret) < minGenericConfidenceLength {
		t.Fatalf("test fixture too short: %d < %d", len(hexSecret), minGenericConfidenceLength)
	}
	d := Detection{Slug: "generic-assigned-secret", Kind: KindGeneric, Length: len(hexSecret)}
	if c := confidenceFor(d, hexSecret, nil); c != "medium" {
		t.Errorf("high-randomness hex secret (avgEntropy=%.4f) should reach medium confidence, got %s",
			averageEntropy(hexSecret), c)
	}
}

// TestConfidenceViaScanner exercises the real materialization path (scanner.go
// redact()) end to end, rather than calling confidenceFor directly, to make
// sure the 256-byte context window is actually wired up from the scanned
// bytes and lands on Detection.Confidence.
func TestConfidenceViaScanner(t *testing.T) {
	s := New()

	// Provider name mentioned near the hit => high.
	withContext := []byte("# talking to github.com\ngithub_token: ghp_0123456789abcdefghijklmnopqrstuvwxyz\n")
	ds := s.ScanText(t.Context(), "config.yaml", withContext, SourceFile)
	got := detectionByCode(ds, "DS-RAT-SEC-004")
	if got == nil {
		t.Fatal("expected github token detection")
	}
	if got.Confidence != "high" {
		t.Errorf("github token with nearby provider mention: Confidence = %q, want high", got.Confidence)
	}

	// Same token, no provider name anywhere nearby => medium.
	noContext := []byte(strings.Repeat("x", 300) + "\ntoken: ghp_0123456789abcdefghijklmnopqrstuvwxyz\n" + strings.Repeat("y", 300))
	ds2 := s.ScanText(t.Context(), "config.yaml", noContext, SourceFile)
	got2 := detectionByCode(ds2, "DS-RAT-SEC-004")
	if got2 == nil {
		t.Fatal("expected github token detection")
	}
	if got2.Confidence != "medium" {
		t.Errorf("github token without nearby provider mention: Confidence = %q, want medium", got2.Confidence)
	}

	// Gating behavior must be unaffected: Entropy field stays Shannon.
	if got.Entropy != shannonEntropy("ghp_0123456789abcdefghijklmnopqrstuvwxyz") {
		t.Errorf("Detection.Entropy should remain plain Shannon entropy, got %v", got.Entropy)
	}
}

func detectionByCode(ds []Detection, code string) *Detection {
	for i := range ds {
		if ds[i].Code == code {
			return &ds[i]
		}
	}
	return nil
}
