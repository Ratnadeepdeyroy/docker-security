package secrets

import (
	"bytes"
	"regexp"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- The provider ruleset ---------------------------------------------------
//
// Rules are data. A rule is a compiled regular expression plus the metadata
// needed to turn a match into a Detection. Adding a provider is a matter of
// appending one entry — no control-flow changes. Regexes are anchored on the
// distinctive, publicly-documented shape of each credential (prefixes, fixed
// lengths, delimiters) so they fire with very few false positives and need no
// entropy gate; where a shape is ambiguous (a bare 40-char base64 blob for an
// AWS secret key) the regex carries its own keyword context.

// Rule is one provider-specific detector.
type Rule struct {
	Code        string          // stable engine RuleID, e.g. "DS-RAT-SEC-001"
	Slug        string          // machine id, e.g. "aws-access-key-id"
	Title       string          // human summary
	Kind        Kind            // category
	Severity    engine.Severity // base severity
	re          *regexp.Regexp  // pattern; the whole match is the "hit"
	group       int             // submatch index holding the secret value (0 = whole match)
	minEntropy  float64         // if > 0, the secret value must meet this Shannon entropy
	binarySafe  bool            // safe to run against binary blobs (distinctive anchor, no entropy gate)
	verifierKey string          // routes to a Verifier when live verification is on
	remediation string
	references  []string

	// anchors is a set of literal substrings, at least one of which is
	// guaranteed to occur in any text re can match (derived by hand from re's
	// mandatory literal spans — the optional/variable parts are never used as
	// an anchor). Before running the full regex over a file, applyProviderRules
	// checks for one of these with a cheap bytes.Contains scan and skips the
	// regex entirely when none is present. This is a pure prefilter: it can
	// only skip files re could never have matched anyway, so it never changes
	// which secrets are found. A nil/empty anchors means no clean literal
	// could be derived (e.g. the pattern is one contiguous character class with
	// no fixed substring) — those rules always run, unfiltered.
	anchors []string
	// anchorFold requests a case-insensitive containment check for anchors,
	// for rules whose regex carries the `(?i)` flag. anchors must already be
	// lowercase when this is set.
	anchorFold bool
}

// commonRemediation is appended to every finding: the single most effective fix
// is to keep build-time secrets out of layers entirely.
const buildKitRemediation = "Remove the credential from the image and rotate it immediately. " +
	"For build-time secrets use BuildKit `--mount=type=secret` (tmpfs, never persisted); " +
	"for runtime, inject from a secrets manager (Vault, AWS/GCP/Azure) rather than baking it in."

// providerRules is the ordered, high-signal detector set. Order is stable so
// output is deterministic. Codes are contiguous and never reused.
var providerRules = compileRules([]Rule{
	{
		Code: "DS-RAT-SEC-001", Slug: "aws-access-key-id", Title: "AWS access key ID",
		Kind: KindCloud, Severity: engine.SeverityHigh, binarySafe: true,
		re:    regexp.MustCompile(`\b((?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|A3T[A-Z0-9])[A-Z0-9]{16})\b`),
		group: 1, verifierKey: "aws",
		anchors:    []string{"AKIA", "ASIA", "AGPA", "AIDA", "AROA", "ANPA", "ANVA", "A3T"},
		references: []string{"CIS-DI-0010", "MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-002", Slug: "aws-secret-access-key", Title: "AWS secret access key",
		Kind: KindCloud, Severity: engine.SeverityCritical,
		// The value alone is an unremarkable 40-char base64 blob, so require the
		// canonical key name nearby to avoid matching every hash in the tree.
		re:    regexp.MustCompile(`(?i)aws_?secret_?access_?key["'\s:=]{1,12}([A-Za-z0-9/+]{40})`),
		group: 1, minEntropy: 4.0, verifierKey: "aws",
		anchors: []string{"secret"}, anchorFold: true,
		references: []string{"CIS-DI-0010", "MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-003", Slug: "gcp-service-account-key", Title: "GCP service-account private key",
		Kind: KindCloud, Severity: engine.SeverityHigh, binarySafe: true,
		re:      regexp.MustCompile(`(?i)"private_key"\s*:\s*"-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		anchors: []string{`"private_key"`}, anchorFold: true,
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-004", Slug: "github-token", Title: "GitHub personal access / OAuth token",
		Kind: KindVCS, Severity: engine.SeverityHigh, binarySafe: true,
		re:    regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36})\b`),
		group: 1, verifierKey: "github",
		anchors:    []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-005", Slug: "github-fine-grained-pat", Title: "GitHub fine-grained PAT",
		Kind: KindVCS, Severity: engine.SeverityHigh, binarySafe: true,
		re:    regexp.MustCompile(`\b(github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})\b`),
		group: 1, verifierKey: "github",
		anchors: []string{"github_pat_"},
	},
	{
		Code: "DS-RAT-SEC-006", Slug: "slack-token", Title: "Slack token",
		Kind: KindMessaging, Severity: engine.SeverityHigh, binarySafe: true,
		re:      regexp.MustCompile(`\b(xox[baprs]-[A-Za-z0-9-]{10,64})\b`),
		group:   1,
		anchors: []string{"xox"},
	},
	{
		Code: "DS-RAT-SEC-007", Slug: "private-key", Title: "Private key block",
		Kind: KindPrivateKey, Severity: engine.SeverityHigh,
		// Deliberately NOT binary-safe. A genuine operational private key is
		// deployed as a readable text artifact (id_rsa, *.pem, *.key, a config
		// value). PEM blocks embedded in compiled shared libraries (e.g. gnutls,
		// openssl) are overwhelmingly built-in *test* keys — scanning binaries for
		// this pattern produces dozens of false positives per image, so the key
		// detector runs on text only. Real leaks in text files are unaffected.
		re:         regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----`),
		anchors:    []string{"PRIVATE KEY-----"},
		references: []string{"MITRE-T1552.004"},
	},
	{
		Code: "DS-RAT-SEC-008", Slug: "jwt", Title: "JSON Web Token",
		Kind: KindJWT, Severity: engine.SeverityMedium,
		re:      regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})`),
		group:   1,
		anchors: []string{"eyJ"},
	},
	{
		Code: "DS-RAT-SEC-009", Slug: "stripe-secret-key", Title: "Stripe secret key",
		Kind: KindPayment, Severity: engine.SeverityCritical, binarySafe: true,
		re:      regexp.MustCompile(`\b((?:sk|rk)_live_[A-Za-z0-9]{24,})\b`),
		group:   1,
		anchors: []string{"sk_live_", "rk_live_"},
	},
	{
		Code: "DS-RAT-SEC-010", Slug: "google-api-key", Title: "Google API key",
		Kind: KindCloud, Severity: engine.SeverityHigh, binarySafe: true,
		re:      regexp.MustCompile(`\b(AIza[A-Za-z0-9_\-]{35})\b`),
		group:   1,
		anchors: []string{"AIza"},
	},
	{
		Code: "DS-RAT-SEC-011", Slug: "sendgrid-api-key", Title: "SendGrid API key",
		Kind: KindMessaging, Severity: engine.SeverityHigh, binarySafe: true,
		re:      regexp.MustCompile(`\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b`),
		group:   1,
		anchors: []string{"SG."},
	},
	{
		Code: "DS-RAT-SEC-012", Slug: "npm-token", Title: "npm access token",
		Kind: KindVCS, Severity: engine.SeverityHigh, binarySafe: true,
		re:      regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`),
		group:   1,
		anchors: []string{"npm_"},
	},
	{
		Code: "DS-RAT-SEC-013", Slug: "db-connection-uri", Title: "Database URI with embedded credentials",
		Kind: KindDatabase, Severity: engine.SeverityHigh,
		// Capture the password (group 2); the whole URI is group 1. We fingerprint
		// the password so the same credential across hosts collapses to one id.
		re:    regexp.MustCompile(`\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?)://[^\s:@/]+:([^\s:@/]{3,})@[^\s/"']+)`),
		group: 2,
		anchors: []string{
			"postgres://", "postgresql://", "mysql://",
			"mongodb://", "mongodb+srv://",
			"redis://", "rediss://", "amqp://", "amqps://",
		},
	},
	{
		Code: "DS-RAT-SEC-021", Slug: "gitlab-pat", Title: "GitLab personal access token",
		Kind: KindVCS, Severity: engine.SeverityHigh, binarySafe: true,
		// GitLab's documented PAT suffix is a 20-char random string; the upper
		// bound keeps an unbounded charclass (which includes `-`/`_`) from
		// swallowing adjacent dash/underscore-joined text into the captured secret.
		re:         regexp.MustCompile(`\b(glpat-[A-Za-z0-9_\-]{20,64})\b`),
		group:      1,
		anchors:    []string{"glpat-"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-022", Slug: "gitlab-pipeline-trigger", Title: "GitLab pipeline trigger token",
		Kind: KindVCS, Severity: engine.SeverityMedium, binarySafe: true,
		re:         regexp.MustCompile(`\b(glptt-[0-9a-f]{40})\b`),
		group:      1,
		anchors:    []string{"glptt-"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-023", Slug: "digitalocean-token", Title: "DigitalOcean API token",
		Kind: KindCloud, Severity: engine.SeverityHigh, binarySafe: true,
		// DigitalOcean's documented v1 prefixes are dop_ (PAT), doo_ (OAuth
		// access token), and dor_ (OAuth refresh token) -- there is no `dos_`
		// token type (DO Spaces uses separate AWS-S3-compatible keys).
		re:         regexp.MustCompile(`\b((?:dop|doo|dor)_v1_[0-9a-f]{64})\b`),
		group:      1,
		anchors:    []string{"dop_v1_", "doo_v1_", "dor_v1_"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-024", Slug: "openai-api-key", Title: "OpenAI API key",
		Kind: KindCloud, Severity: engine.SeverityHigh, binarySafe: true,
		re:         regexp.MustCompile(`\b(sk-(?:proj-)?[A-Za-z0-9_\-]{16,}T3BlbkFJ[A-Za-z0-9_\-]{16,})\b`),
		group:      1,
		anchors:    []string{"T3BlbkFJ"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-025", Slug: "anthropic-api-key", Title: "Anthropic API key",
		Kind: KindCloud, Severity: engine.SeverityHigh, binarySafe: true,
		re:         regexp.MustCompile(`\b(sk-ant-[a-z0-9]{2,8}-[A-Za-z0-9_\-]{80,120})\b`),
		group:      1,
		anchors:    []string{"sk-ant-"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-026", Slug: "huggingface-token", Title: "Hugging Face access token",
		Kind: KindCloud, Severity: engine.SeverityHigh, binarySafe: true,
		re:         regexp.MustCompile(`\b(hf_[A-Za-z0-9]{34,40})\b`),
		group:      1,
		anchors:    []string{"hf_"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-027", Slug: "shopify-access-token", Title: "Shopify access token",
		// High, not Critical like Stripe/Square: a Shopify access token (shpat_/
		// shpca_/shppa_) is scoped to the single store/app that issued it, not a
		// full merchant account -- unlike a Stripe/Square secret key, which grants
		// full account-level payment-processing control. Same KindPayment bucket,
		// one tier lower blast radius.
		Kind: KindPayment, Severity: engine.SeverityHigh, binarySafe: true,
		re:         regexp.MustCompile(`\b(shp(?:at|ca|pa)_[0-9a-fA-F]{32})\b`),
		group:      1,
		anchors:    []string{"shpat_", "shpca_", "shppa_"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-028", Slug: "shopify-shared-secret", Title: "Shopify shared secret",
		// See DS-RAT-SEC-027: same app/store-scoped rationale for High over Critical.
		Kind: KindPayment, Severity: engine.SeverityHigh, binarySafe: true,
		re:         regexp.MustCompile(`\b(shpss_[0-9a-fA-F]{32})\b`),
		group:      1,
		anchors:    []string{"shpss_"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-029", Slug: "twilio-api-key", Title: "Twilio API key SID",
		Kind: KindMessaging, Severity: engine.SeverityMedium,
		// SK + 32 hex collides with generic hex (cache keys, checksums, and
		// truncated SHAs land in the same entropy band), so entropy alone is
		// not a reliable gate. Require the "twilio" keyword nearby instead.
		re:      regexp.MustCompile(`(?i)twilio[^\n]{0,40}?\b(SK[0-9a-f]{32})\b`),
		group:   1,
		anchors: []string{"twilio"}, anchorFold: true,
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-030", Slug: "hashicorp-vault-token", Title: "HashiCorp Vault token",
		Kind: KindCloud, Severity: engine.SeverityCritical, binarySafe: true,
		// Upper bound keeps the unbounded `-`/`_`-inclusive charclass from
		// swallowing adjacent dash/underscore-joined text into the captured secret.
		re:         regexp.MustCompile(`\b(hv[sbr]\.[A-Za-z0-9_\-]{24,64})\b`),
		group:      1,
		anchors:    []string{"hvs.", "hvb.", "hvr."},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-031", Slug: "telegram-bot-token", Title: "Telegram bot token",
		Kind: KindMessaging, Severity: engine.SeverityMedium, binarySafe: true,
		re:         regexp.MustCompile(`\b(\d{8,10}:AA[A-Za-z0-9_\-]{32,34})\b`),
		group:      1,
		anchors:    []string{":AA"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-032", Slug: "discord-webhook", Title: "Discord webhook URL",
		Kind: KindMessaging, Severity: engine.SeverityMedium, binarySafe: true,
		re:         regexp.MustCompile(`(https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]{40,})`),
		group:      1,
		anchors:    []string{"discord.com/api/webhooks/", "discordapp.com/api/webhooks/"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-033", Slug: "pypi-token", Title: "PyPI upload token",
		Kind: KindVCS, Severity: engine.SeverityHigh, binarySafe: true,
		// PyPI upload tokens are base64-encoded macaroons and routinely run past
		// 150 characters, so the cap is generous relative to the other
		// providers' fixed-length tokens -- still bounded rather than open-ended,
		// so adjacent dash/underscore text cannot be swallowed into the secret.
		re:         regexp.MustCompile(`\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,200})`),
		group:      1,
		anchors:    []string{"pypi-AgEIcHlwaS5vcmc"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-034", Slug: "rubygems-key", Title: "RubyGems API key",
		Kind: KindVCS, Severity: engine.SeverityHigh, binarySafe: true,
		re:         regexp.MustCompile(`\b(rubygems_[0-9a-f]{48})\b`),
		group:      1,
		anchors:    []string{"rubygems_"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-035", Slug: "square-access-token", Title: "Square access token",
		Kind: KindPayment, Severity: engine.SeverityCritical, binarySafe: true,
		re:         regexp.MustCompile(`\b(sq0atp-[A-Za-z0-9_\-]{22})\b`),
		group:      1,
		anchors:    []string{"sq0atp-"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-036", Slug: "mailgun-key", Title: "Mailgun API key",
		Kind: KindMessaging, Severity: engine.SeverityMedium,
		// "key-"+32hex is weakly shaped (collides with cache keys, checksums,
		// etc.), so demand the mailgun keyword nearby rather than falling back
		// to a bare-pattern/entropy gate.
		re:      regexp.MustCompile(`(?i)mailgun[^\n]{0,40}?\b(key-[0-9a-f]{32})\b`),
		group:   1,
		anchors: []string{"mailgun"}, anchorFold: true,
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-037", Slug: "mailchimp-key", Title: "Mailchimp API key",
		Kind: KindMessaging, Severity: engine.SeverityMedium, binarySafe: true,
		// No clean literal anchor: the pattern is a bare hex blob plus a
		// "-us<digits>" suffix, with no fixed-case/fixed-position substring
		// that is both mandatory and distinctive enough to gate on. Runs
		// unfiltered (the fallback case).
		re:         regexp.MustCompile(`\b([0-9a-f]{32}-us\d{1,2})\b`),
		group:      1,
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-038", Slug: "grafana-service-account", Title: "Grafana service-account token",
		Kind: KindCloud, Severity: engine.SeverityHigh, binarySafe: true,
		re:         regexp.MustCompile(`\b(glsa_[A-Za-z0-9]{32}_[0-9a-f]{8})\b`),
		group:      1,
		anchors:    []string{"glsa_"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-039", Slug: "postman-api-key", Title: "Postman API key",
		Kind: KindCloud, Severity: engine.SeverityMedium, binarySafe: true,
		re:         regexp.MustCompile(`\b(PMAK-[0-9a-f]{24}-[0-9a-f]{34})\b`),
		group:      1,
		anchors:    []string{"PMAK-"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-040", Slug: "airtable-pat", Title: "Airtable personal access token",
		Kind: KindCloud, Severity: engine.SeverityMedium, binarySafe: true,
		re:         regexp.MustCompile(`\b(pat[A-Za-z0-9]{14}\.[0-9a-f]{64})\b`),
		group:      1,
		anchors:    []string{"pat"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-041", Slug: "figma-pat", Title: "Figma personal access token",
		Kind: KindCloud, Severity: engine.SeverityMedium, binarySafe: true,
		// Upper bound keeps the unbounded `-`/`_`-inclusive charclass from
		// swallowing adjacent dash/underscore-joined text into the captured secret.
		re:         regexp.MustCompile(`\b(figd_[A-Za-z0-9_\-]{40,64})\b`),
		group:      1,
		anchors:    []string{"figd_"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-042", Slug: "dockerhub-pat", Title: "Docker Hub personal access token",
		Kind: KindVCS, Severity: engine.SeverityHigh, binarySafe: true,
		// Upper bound keeps the unbounded `-`/`_`-inclusive charclass from
		// swallowing adjacent dash/underscore-joined text into the captured secret.
		re:         regexp.MustCompile(`\b(dckr_pat_[A-Za-z0-9_\-]{27,64})\b`),
		group:      1,
		anchors:    []string{"dckr_pat_"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-043", Slug: "sentry-dsn", Title: "Sentry DSN with secret",
		Kind: KindGeneric, Severity: engine.SeverityLow, binarySafe: true,
		// Modern Sentry DSNs are a single public key
		// (`https://<pubkey>@o<org>.ingest.sentry.io/<project>`), and Sentry's own
		// docs describe that shape as safe to embed in client-side/public code --
		// matching only the public form would fire on essentially every image
		// bundling a Sentry SDK config, none of which are real leaks. Sentry's
		// now-deprecated legacy DSN carried a *second* credential half after a
		// colon (`https://<pubkey>:<secretkey>@...`); only that two-part shape is
		// an actual secret, so the regex requires both halves.
		re:         regexp.MustCompile(`(https://[0-9a-f]{32}:[0-9a-f]{32}@o\d+\.ingest\.sentry\.io/\d+)`),
		group:      1,
		anchors:    []string{".ingest.sentry.io/"},
		references: []string{"MITRE-T1552.001"},
	},
	{
		Code: "DS-RAT-SEC-044", Slug: "mapbox-secret-token", Title: "Mapbox secret token",
		Kind: KindCloud, Severity: engine.SeverityMedium, binarySafe: true,
		re:         regexp.MustCompile(`\b(sk\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]{20,})\b`),
		group:      1,
		anchors:    []string{"sk.eyJ"},
		references: []string{"MITRE-T1552.001"},
	},
})

// compileRules attaches the shared remediation default to any rule that omits
// its own and returns the ruleset ready to use.
func compileRules(rs []Rule) []Rule {
	for i := range rs {
		if rs[i].remediation == "" {
			rs[i].remediation = buildKitRemediation
		}
	}
	return rs
}

// providerRegexRuns counts full-regex executions inside applyProviderRules.
// It exists purely so tests can verify the anchor prefilter below is actually
// skipping rules rather than running every regex unconditionally; production
// code never reads it. The increment is a single unsynchronized int add, so
// it costs nothing worth measuring relative to a regexp scan.
var providerRegexRuns int

// hasAnchor reports whether data (or its lowercase form foldData, computed
// lazily by the caller and shared across every fold-anchored rule) could
// possibly match r's regex, using r's precomputed literal anchor(s) as a
// cheap necessary-condition check. It never produces a false negative: every
// anchor is a literal substring that r.re's mandatory (non-optional) text is
// guaranteed to contain, so any real match still passes this check. A rule
// with no anchors (anchors == nil) has no clean literal to gate on and always
// runs.
func hasAnchor(data, foldData []byte, r *Rule) bool {
	if len(r.anchors) == 0 {
		return true
	}
	hay := data
	if r.anchorFold {
		hay = foldData
	}
	for _, a := range r.anchors {
		if bytes.Contains(hay, []byte(a)) {
			return true
		}
	}
	return false
}

// applyProviderRules runs every provider rule over data and returns raw hits
// (value included, for fingerprinting/verification only — never stored). When
// binaryOnly is set (a binary blob), only binary-safe rules run: the anchored,
// no-entropy-gate detectors that will not fire on random bytes.
//
// Before running a rule's full regex (an O(len(data)) scan on its own), a
// cheap bytes.Contains prefilter checks for a literal substring the match must
// contain (see Rule.anchors). Most files contain none of the ~35 distinct
// provider anchors, so this turns "37 full regex passes per file" into
// "37 substring scans plus a handful of regex passes" for the common case —
// with no change in which secrets are found, since the anchor check can only
// skip a rule the regex could never have matched anyway. The lowercase copy
// needed by the handful of case-insensitive rules is computed at most once
// per call, on first use, not once per fold-anchored rule.
func applyProviderRules(data []byte, binaryOnly bool) []rawHit {
	var hits []rawHit
	var foldData []byte
	var foldComputed bool
	for i := range providerRules {
		r := &providerRules[i]
		if binaryOnly && !r.binarySafe {
			continue
		}
		if r.anchorFold && !foldComputed {
			foldData = bytes.ToLower(data)
			foldComputed = true
		}
		if !hasAnchor(data, foldData, r) {
			continue
		}
		providerRegexRuns++
		for _, m := range r.re.FindAllSubmatchIndex(data, -1) {
			// m holds [wholeStart,wholeEnd, g1Start,g1End, ...]. Extract the
			// secret group (0 => whole match) and the whole-match start for line.
			secStart, secEnd := m[0], m[1]
			if r.group > 0 && 2*r.group+1 < len(m) && m[2*r.group] >= 0 {
				secStart, secEnd = m[2*r.group], m[2*r.group+1]
			}
			secret := string(data[secStart:secEnd])
			if r.minEntropy > 0 && shannonEntropy(secret) < r.minEntropy {
				continue
			}
			hits = append(hits, rawHit{
				rule:   r,
				secret: secret,
				offset: m[0],
			})
		}
	}
	return hits
}

// rawHit is a match before redaction: it still holds the secret value, which
// exists only long enough to fingerprint (and optionally verify) it.
type rawHit struct {
	rule   *Rule
	secret string
	offset int
	// slug/severity overrides for the generic detectors, which share the
	// Detection plumbing but are not backed by a providerRules entry.
	generic *genericMeta
}

// genericMeta carries the identity of a generic (non-provider) detection.
type genericMeta struct {
	code, slug, title, remediation string
	kind                           Kind
	severity                       engine.Severity
	references                     []string
}
