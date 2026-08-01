package secrets

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Generic heuristics -----------------------------------------------------
//
// Provider rules catch known shapes; these two detectors catch the rest. They
// are where false positives are born, so both are conservative:
//
//   - detectAssignments fires only when a secret-looking *key name* is assigned
//     a high-entropy, non-placeholder value. The key-name context is what keeps
//     it quiet on ordinary config. This runs by default.
//   - detectBareEntropy sweeps for high-entropy tokens with no key context at
//     all. On its own that is far too noisy, so it runs ONLY when a semantic
//     Classifier is supplied to judge each candidate. It is off by default.

// assignRe matches `key = value` / `key: value`, optionally quoted. It is
// deliberately loose on the value charset; the entropy and placeholder filters
// do the discriminating. The value floor is 5, not 8: a value shorter than 10
// characters can never reach minAssignEntropy even in the all-unique-character
// best case (log2(9) < 3.2 < log2(10)), so widening the floor to 5 only ever
// feeds the low-entropy branch below — it can never produce a new DS-RAT-SEC-014
// (strong secret) match, only a candidate for the weak-password check.
var assignRe = regexp.MustCompile(`(?i)([A-Za-z0-9_.\-]{1,64})\s*[:=]\s*["']?([A-Za-z0-9+/=_.\-]{5,128})["']?`)

// xmlKVRe matches <tag>value</tag> where tag is a plausible identifier and the
// value is a single whitespace-free token (config-shaped, not document text).
// This is the classic Maven settings.xml / Tomcat server.xml / .NET
// web.config leak shape: the key lives in the tag name, not in a `k=v`
// assignment, so assignRe never sees it. Go's stdlib regexp (RE2) has no
// backreferences, so the closing tag is not required to literally match the
// opening one — it only needs to look like a well-formed closer. A mismatched
// pair (hand-edited or truncated XML) therefore may still match; that is an
// accepted limitation of a backtracking-free engine, not a crash risk.
//
// The value charset is `[^\s<>]` (any non-whitespace, non-angle-bracket run),
// not assignRe's stricter `[A-Za-z0-9+/=_.\-]`: a real password can carry
// symbols assignRe's charset would exclude (e.g. `k9#Qz7$mP2xW`), so the
// token class here is widened to admit them. What it must still reject is
// document prose — help text like
// `<password>Must be 8+ characters, include a number.</password>` — and
// excluding whitespace does that: the surrounding `\s*` only consumes
// whitespace immediately adjacent to the tags, so a multi-word value can
// never satisfy the pattern (the captured run would have to stop at the
// first space, and nothing after that point can be skipped over to reach the
// closing tag). The `\s*` also means a value with incidental leading/trailing
// whitespace (`<password> abc123 </password>`) is captured already trimmed.
var xmlKVRe = regexp.MustCompile(`<([A-Za-z][A-Za-z0-9_.\-]{2,40})>\s*([^\s<>]{5,128})\s*</[A-Za-z][A-Za-z0-9_.\-]{2,40}>`)

// secretKeyRe matches key names that conventionally hold credentials. Anchoring
// the assignment detector on this list is the single biggest false-positive
// reducer in the whole engine.
var secretKeyRe = regexp.MustCompile(`(?i)(pass(word|wd)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|refresh[_-]?token|credential|bearer|passphrase)`)

// minAssignEntropy is the Shannon-entropy floor for an assigned value. 3.2 bits
// clears short random tokens and strong passwords while rejecting words and
// simple identifiers.
const minAssignEntropy = 3.2

// bareTokenRe extracts long, dense tokens for the classifier-gated sweep.
var bareTokenRe = regexp.MustCompile(`[A-Za-z0-9+/=_\-]{24,128}`)

// minBareEntropy is the (higher) floor for a context-free token: without a key
// name to lean on we demand more randomness before even asking the classifier.
const minBareEntropy = 4.2

// detectAssignments finds `secretKey = highEntropyValue` pairs. It is the
// default generic detector.
func detectAssignments(path string, data []byte) []rawHit {
	sourceCode := isSourceCodePath(path)
	var hits []rawHit
	for _, m := range assignRe.FindAllSubmatchIndex(data, -1) {
		key := string(data[m[2]:m[3]])
		val := string(data[m[4]:m[5]])
		if !secretKeyRe.MatchString(key) {
			continue
		}
		if isPlaceholder(val) {
			continue
		}
		if shannonEntropy(val) < minAssignEntropy {
			// Not random enough to be a machine credential — but a human
			// password assigned to a password-named key in a *config* file is
			// still a leaked credential, and a weak one at that. Source files
			// are excluded: `password = "hunter2"` in application code is far
			// too noisy a shape to flag (test fixtures, string literals used
			// as prompts, etc.).
			if !sourceCode && isWeakPasswordKey(key) && plausibleWeakPassword(val) {
				hits = append(hits, rawHit{
					secret: val,
					offset: m[4],
					generic: &genericMeta{
						code: "DS-RAT-SEC-050", slug: "weak-hardcoded-password",
						title: "Weak hardcoded password in config",
						kind:  KindGeneric, severity: engine.SeverityMedium,
						remediation: "Remove the literal password and inject it at runtime from a secrets manager; rotate it, and enforce a password policy (length >= 16, generated).",
					},
				})
			}
			continue
		}
		// Reject values that look like source code, not a credential. Scanning a
		// source tree, `token = get_unstructured`, `secret = self.value`, or
		// `key = WRAPPER_ASSIGNMENTS` all match `secretKey = value` yet assign an
		// identifier/attribute, not a literal — the dominant false positive on a
		// real image's language runtime (Python stdlib, etc.).
		if !plausibleSecretValue(val) {
			continue
		}
		// In a source-code file, the assignment heuristic is meant for embedded
		// *literals*. A bare (unquoted) right-hand side there is a variable or
		// call, not a secret — require quotes. Config files (.env, yaml, ini …)
		// legitimately carry unquoted values, so they are exempt.
		if sourceCode && !valueQuoted(data, m[4], m[5]) {
			continue
		}
		hits = append(hits, rawHit{
			secret: val,
			offset: m[4],
			generic: &genericMeta{
				code: "DS-RAT-SEC-014", slug: "generic-assigned-secret",
				title: "Hardcoded credential assigned to a secret-named key",
				kind:  KindGeneric, severity: engine.SeverityHigh,
				remediation: buildKitRemediation,
				references:  []string{"CIS-DI-0010", "MITRE-T1552.001"},
			},
		})
	}
	// XML configs put the key in the tag name rather than in a `k=v`
	// assignment: <password>value</password>. Same filtering pipeline as the
	// k=v path above (secretKeyRe on the tag name, placeholder + entropy
	// floor, plausibleSecretValue), so this is intentionally narrower: it does
	// not run the weak-password (DS-RAT-SEC-050) fallback, since that path's
	// human-chosen-literal shape needs the source/config distinction the k=v
	// loop already makes and is left as future work for the XML shape.
	for _, m := range xmlKVRe.FindAllSubmatchIndex(data, -1) {
		key := string(data[m[2]:m[3]])
		val := string(data[m[4]:m[5]])
		if !secretKeyRe.MatchString(key) {
			continue
		}
		if isPlaceholder(val) || shannonEntropy(val) < minAssignEntropy {
			continue
		}
		if !plausibleXMLSecretValue(val) {
			continue
		}
		hits = append(hits, rawHit{
			secret: val,
			offset: m[4],
			generic: &genericMeta{
				code: "DS-RAT-SEC-051", slug: "xml-config-credential",
				title: "Hardcoded credential in XML configuration",
				kind:  KindGeneric, severity: engine.SeverityHigh,
				remediation: buildKitRemediation,
			},
		})
	}
	return hits
}

// plausibleSecretValue reports whether an assigned value has the shape of a real
// credential rather than a code identifier or word. Real API keys, tokens, and
// generated passwords carry a distinguishing signal: a digit, a base64/token
// symbol (+ / =), or mixed upper/lower case. A bare single-case run of letters,
// underscores, dots, or hyphens (a variable, attribute, dictionary word, or
// dotted path) carries none and is accepted only if its entropy is high enough
// to be genuinely random. This is the single biggest source-tree FP reducer.
func plausibleSecretValue(val string) bool {
	hasDigit := strings.ContainsAny(val, "0123456789")
	hasTokenSym := strings.ContainsAny(val, "+/=") // base64 / token punctuation
	hasUpper := val != strings.ToLower(val)
	hasLower := val != strings.ToUpper(val)
	if hasDigit || hasTokenSym || (hasUpper && hasLower) {
		return true
	}
	// No credential signal: treat as code/prose unless it is highly random.
	return shannonEntropy(val) >= 4.0
}

// plausibleXMLSecretValue tightens plausibleSecretValue for the XML tag-value
// shape. plausibleSecretValue's mixed-case shortcut (any value with both
// upper and lower case letters passes unconditionally, no entropy check) is
// exploitable by an instructional/placeholder phrase written as a single
// camelCase or PascalCase word with no digits or symbols -- e.g.
// "SetViaEnvironmentVariable" left in a settings.xml template as a note to
// the reader ("don't hardcode this, set it via env"), not a credential. XML
// tag values have no spaces to lean on for a prose check (xmlKVRe's charset
// already excludes them, see the doc comment above), so this shape slips
// past the same filters that catch multi-word prose. Require the same
// >=4.0 entropy fallback the single-case branch already uses whenever the
// value carries neither a digit nor any other symbol, rather than passing on
// case-mixing alone. Real symbol-rich passwords (e.g. "k9#Qz7$mP2xW") are
// unaffected -- they clear the hasSymbol check immediately.
func plausibleXMLSecretValue(val string) bool {
	hasDigit := strings.ContainsAny(val, "0123456789")
	hasSymbol := false
	for i := 0; i < len(val); i++ {
		c := val[i]
		if !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
			hasSymbol = true
			break
		}
	}
	if hasDigit || hasSymbol {
		return true
	}
	return shannonEntropy(val) >= 4.0
}

// weakKeyRe is narrower than secretKeyRe: only key names that hold an actual
// password/secret value, not key-material policy knobs (PASSWORD_MIN_LENGTH,
// PASSWORD_ENABLED). Anchored on both ends so a key must *end* in one of
// these words (after an optional `..._` prefix), not merely contain one.
var weakKeyRe = regexp.MustCompile(`(?i)^(.*_)?(pass(word|wd)?|pwd|secret|passphrase)$`)

// isWeakPasswordKey reports whether key names a literal password/secret value.
func isWeakPasswordKey(key string) bool { return weakKeyRe.MatchString(key) }

// plausibleWeakPassword accepts short human-chosen literals while rejecting
// numbers, booleans, and other single-word config values that are not
// passwords (a size/limit, a feature flag, or a schema/doc type placeholder
// such as the "string" in a README's `| DB_PASSWORD | string | required |`
// env-var table).
func plausibleWeakPassword(val string) bool {
	if len(val) < 5 || len(val) > 64 {
		return false
	}
	if _, err := strconv.Atoi(val); err == nil {
		return false // pure number: a size/limit, not a password
	}
	switch strings.ToLower(val) {
	case "true", "false", "yes", "no", "on", "off", "none", "null", "disabled", "enabled":
		return false
	// Schema/doc type-placeholder words: these recur endlessly in README
	// env-var tables, OpenAPI/JSON-Schema-ish docs, and Terraform variable
	// descriptions as the *type* half of a `password: <word>` row, not a
	// credential.
	case "string", "text", "integer", "int", "number", "boolean", "bool",
		"required", "optional", "example", "changeme":
		return false
	}
	return true
}

// sourceCodeExts are compiled/interpreted source extensions where `key = value`
// is variable assignment, not configuration. The generic assignment detector
// requires a quoted literal in these files; the distinctive provider rules still
// run everywhere, so a real hardcoded AWS/GitHub/… token in source is unaffected.
var sourceCodeExts = map[string]bool{
	".py": true, ".pyi": true, ".go": true, ".js": true, ".mjs": true, ".cjs": true,
	".ts": true, ".tsx": true, ".jsx": true, ".java": true, ".kt": true, ".kts": true,
	".c": true, ".cc": true, ".cpp": true, ".cxx": true, ".h": true, ".hpp": true,
	".rb": true, ".rs": true, ".php": true, ".scala": true, ".swift": true, ".lua": true,
	".pl": true, ".pm": true, ".r": true, ".groovy": true, ".dart": true, ".ex": true,
	".exs": true, ".clj": true, ".cs": true, ".m": true, ".mm": true,
}

// isSourceCodePath reports whether path is a source file (by extension).
func isSourceCodePath(path string) bool {
	dot := strings.LastIndexByte(path, '.')
	if dot < 0 {
		return false
	}
	return sourceCodeExts[strings.ToLower(path[dot:])]
}

// valueQuoted reports whether the value spanning [start,end) in data is wrapped
// in matching single or double quotes.
func valueQuoted(data []byte, start, end int) bool {
	if start-1 < 0 || end >= len(data) {
		return false
	}
	q := data[start-1]
	return (q == '"' || q == '\'') && data[end] == q
}

// detectBareEntropy sweeps for context-free high-entropy tokens and asks the
// classifier whether each is plausibly a credential. It emits nothing unless a
// classifier accepts a candidate, so a nil classifier means this detector is a
// no-op — the AI-age recall boost stays strictly off by default.
func detectBareEntropy(data []byte, c Classifier) []rawHit {
	if c == nil {
		return nil
	}
	var hits []rawHit
	seen := map[string]bool{}
	for _, loc := range bareTokenRe.FindAllIndex(data, -1) {
		tok := string(data[loc[0]:loc[1]])
		if seen[tok] {
			continue
		}
		seen[tok] = true
		if shannonEntropy(tok) < minBareEntropy || isPlaceholder(tok) {
			continue
		}
		if v := c.Classify(Candidate{Value: tok, Entropy: shannonEntropy(tok)}); !v.IsSecret {
			continue
		}
		hits = append(hits, rawHit{
			secret: tok,
			offset: loc[0],
			generic: &genericMeta{
				code: "DS-RAT-SEC-015", slug: "high-entropy-string",
				title: "High-entropy string classified as a likely secret",
				kind:  KindGeneric, severity: engine.SeverityMedium,
				remediation: buildKitRemediation,
				references:  []string{"MITRE-T1552.001"},
			},
		})
	}
	return hits
}

// placeholders are common non-secret values that look secret-shaped. Matching
// any of these (case-insensitively) suppresses a finding.
var placeholders = map[string]bool{
	"password": true, "passw0rd": true, "changeme": true, "secret": true,
	"token": true, "example": true, "examplekey": true, "test": true,
	"null": true, "none": true, "true": true, "false": true, "undefined": true,
	"placeholder": true, "redacted": true, "yourpassword": true, "yourapikey": true,
}

// sriRe matches subresource-integrity / checksum-style values
// (`sha256-<hash>`, `integrity=sha384-<hash>`). These recur endlessly in
// vendored web assets (script/link integrity attributes) and lockfiles, and
// are checksums, not credentials. The algorithm is anchored to the four SRI
// digests (sha1/256/384/512) and the part after the dash must look like an
// actual base64/hex digest — at least 16 characters of digest alphabet,
// anchored to end-of-string. Without that length floor, a real secret that
// merely starts with "sha-" (e.g. "sha-my-actual-password-123") would match
// on prefix alone and be wrongly suppressed.
//
// mimeRe matches a bare MIME type (`type/subtype`) restricted to a curated
// set of common real IANA subtypes, e.g. "image/png", "application/json". An
// open subtype charset would match any `namespace/token`-shaped secret (e.g.
// "application/x-my-secret-token-here"); enumerating real subtypes closes
// that hole. It is anchored end-to-end so it only matches a bare MIME
// string, not a Content-Type header value carrying parameters (e.g.
// "text/html; charset=utf-8") — those are not screened out by this check,
// since a parameterized value is a different, less common shape that this
// hardening pass does not need to cover.
var (
	sriRe  = regexp.MustCompile(`^(integrity=)?sha(1|256|384|512)-[a-z0-9+/=_-]{16,}$`)
	mimeRe = regexp.MustCompile(`^(application|image|text|audio|video|font)/(json|xml|octet-stream|plain|html|css|javascript|pdf|zip|gzip|x-www-form-urlencoded|png|jpe?g|gif|webp|svg\+xml|wasm|woff2?|ttf|otf|csv)$`)
)

// isPlaceholder reports whether val is an obvious non-secret: a known dummy, an
// env-var reference, a template, a run of a single repeated character, or one
// of the non-secret structural families (data URIs, SRI/checksum prefixes,
// bare MIME types).
func isPlaceholder(val string) bool {
	low := strings.ToLower(val)
	if placeholders[low] {
		return true
	}
	// Note: no "<"/">" markers here. Every value reaching this function comes
	// from assignRe ([A-Za-z0-9+/=_.\-]{5,128}), xmlKVRe ([^\s<>]{5,128}, which
	// excludes angle brackets by construction so it stops at the closing tag),
	// or bareTokenRe ([A-Za-z0-9+/=_\-]{24,128}) -- all three charsets already
	// exclude "<"/">", so a captured value can never contain one. Markers for
	// that shape were dead code and have been removed.
	for _, marker := range []string{"example", "changeme", "your_", "your-", "placeholder", "dummy", "sample", "xxxxx"} {
		if strings.Contains(low, marker) {
			return true
		}
	}
	// Non-secret structural families: data URIs, subresource-integrity /
	// checksum prefixes, bare MIME types. These recur endlessly in vendored
	// web assets and lockfiles and are never credentials.
	if strings.HasPrefix(low, "data:") {
		return true
	}
	if sriRe.MatchString(low) {
		return true
	}
	if mimeRe.MatchString(low) {
		return true
	}
	// Env-var / template references: $VAR, ${VAR}, %VAR%, {{ .Var }}.
	if strings.HasPrefix(val, "$") || strings.HasPrefix(val, "${") || strings.HasPrefix(val, "%") || strings.Contains(val, "{{") {
		return true
	}
	// A single repeated character carries no secret.
	if allSameByte(val) {
		return true
	}
	return false
}

func allSameByte(s string) bool {
	if len(s) < 2 {
		return true
	}
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}
