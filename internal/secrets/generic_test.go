package secrets

import (
	"context"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// TestDetectWeakPassword locks in DS-RAT-SEC-050: a literal, low-entropy password
// assigned to a password-named key in a config file must be flagged. This is
// the exact shape (`DB_PASSWORD=hunter2`) that a plain entropy-gated detector
// misses — high-entropy floors are backwards for a *weak* credential.
func TestDetectWeakPassword(t *testing.T) {
	data := []byte("DB_PASSWORD=hunter2\n")
	hits := detectAssignments("app/config.env", data)
	found := false
	for _, h := range hits {
		if h.generic != nil && h.generic.slug == "weak-hardcoded-password" {
			found = true
			if h.generic.code != "DS-RAT-SEC-050" {
				t.Errorf("code = %q, want DS-RAT-SEC-050", h.generic.code)
			}
			if h.generic.severity != engine.SeverityMedium {
				t.Errorf("severity = %v, want Medium", h.generic.severity)
			}
		}
	}
	if !found {
		t.Fatalf("weak password not detected: %+v", hits)
	}
}

// TestWeakPasswordSuppressed enumerates the false-positive shapes the brief
// calls out: placeholders, source code, env references, non-secret keys, and
// numeric policy knobs must never fire DS-RAT-SEC-050.
func TestWeakPasswordSuppressed(t *testing.T) {
	cases := []struct {
		path string
		data string
	}{
		{"app/config.env", "DB_PASSWORD=changeme"},   // placeholder
		{"app/main.py", `password = "hunter2"`},      // source code: skip
		{"app/config.env", "DB_PASSWORD=$SECRET"},    // env reference
		{"app/config.env", "DB_HOST=localhost"},      // not a secret key
		{"app/config.env", "PASSWORD_MIN_LENGTH=12"}, // numeric policy value
	}
	for _, c := range cases {
		for _, h := range detectAssignments(c.path, []byte(c.data)) {
			if h.generic != nil && h.generic.slug == "weak-hardcoded-password" {
				t.Errorf("%s %q: false positive", c.path, c.data)
			}
		}
	}
}

// TestWeakPasswordMixedWithStrongSecret exercises the fixture that motivated
// this task: a real .env commonly carries both a strong, high-entropy API key
// AND a weak, human-chosen password. Both must be detected independently, and
// neither assignment should be double-counted under the other's rule.
func TestWeakPasswordMixedWithStrongSecret(t *testing.T) {
	data := []byte("API_TOKEN=xY9zK2mN4pQ7rS1tU3vW\nDB_PASSWORD=hunter2\n")
	hits := detectAssignments("app/config.env", data)

	var strong, weak int
	for _, h := range hits {
		if h.generic == nil {
			continue
		}
		switch h.generic.slug {
		case "generic-assigned-secret":
			strong++
			if h.secret != "xY9zK2mN4pQ7rS1tU3vW" {
				t.Errorf("strong hit carries wrong secret: %q", h.secret)
			}
		case "weak-hardcoded-password":
			weak++
			if h.secret != "hunter2" {
				t.Errorf("weak hit carries wrong secret: %q", h.secret)
			}
		}
	}
	if strong != 1 {
		t.Errorf("strong secret hits = %d, want 1", strong)
	}
	if weak != 1 {
		t.Errorf("weak password hits = %d, want 1", weak)
	}
}

// TestWeakPasswordSchemaPlaceholderSuppressed locks in the fix for a
// polish-lens false positive: `DB_PASSWORD: string` is a schema/doc type
// row (the kind of line that recurs endlessly in README env-var tables,
// e.g. `| DB_PASSWORD | string | required |`), not a literal password, but
// "string" cleared the old plausibleWeakPassword check (not numeric, not a
// recognized boolean/null word). Common type/schema stub words must now be
// rejected too.
func TestWeakPasswordSchemaPlaceholderSuppressed(t *testing.T) {
	cases := []string{
		"string", "text", "integer", "int", "number", "boolean", "bool",
		"required", "optional", "none", "null", "example", "changeme",
		"String", "BOOLEAN", "Required", // case-insensitive
	}
	for _, val := range cases {
		data := []byte("DB_PASSWORD: " + val + "\n")
		for _, h := range detectAssignments("README.md", data) {
			if h.generic != nil && h.generic.slug == "weak-hardcoded-password" {
				t.Errorf("DB_PASSWORD: %s: schema/doc placeholder must not be flagged as DS-RAT-SEC-050", val)
			}
		}
	}
	// A genuine weak password must still fire alongside the fix.
	if !plausibleWeakPassword("hunter2") {
		t.Error("plausibleWeakPassword(\"hunter2\") = false, want true (real weak password unaffected)")
	}
}

// TestWeakPasswordSourcePythonSuppressed is a second, explicit source-code
// shape (distinct from the inline case in TestWeakPasswordSuppressed) to make
// sure the source-code exclusion isn't accidentally keyed off the literal
// string used above.
func TestWeakPasswordSourcePythonSuppressed(t *testing.T) {
	data := []byte("DB_PASSWORD = \"hunter2\"\n")
	for _, h := range detectAssignments("app/settings.py", data) {
		if h.generic != nil && h.generic.slug == "weak-hardcoded-password" {
			t.Errorf("weak password must be suppressed in source code, got: %+v", h)
		}
	}
}

// TestWeakPasswordYAML confirms the `key: value` (colon) assignment shape
// used by YAML config files is detected, not just the `key=value` .env shape.
func TestWeakPasswordYAML(t *testing.T) {
	data := []byte("password: hunter2\n")
	found := false
	for _, h := range detectAssignments("app/config.yaml", data) {
		if h.generic != nil && h.generic.slug == "weak-hardcoded-password" {
			found = true
		}
	}
	if !found {
		t.Fatalf("weak password in YAML config not detected")
	}
}

// TestWeakPasswordNumericSuppressed pins down the numeric-policy-value false
// positive: PASSWORD_MIN_LENGTH=12 is a length knob, not a password, and its
// key does not even match the weak-password key shape (it does not end in
// pass/pwd/secret/passphrase).
func TestWeakPasswordNumericSuppressed(t *testing.T) {
	data := []byte("PASSWORD_MIN_LENGTH=12\n")
	for _, h := range detectAssignments("app/config.env", data) {
		if h.generic != nil && h.generic.slug == "weak-hardcoded-password" {
			t.Errorf("numeric policy value must not be flagged as a weak password, got: %+v", h)
		}
	}
}

// TestWeakPasswordBooleanSuppressed pins down the boolean-flag false
// positive: PASSWORD_ENABLED=true is a feature toggle, not a password.
func TestWeakPasswordBooleanSuppressed(t *testing.T) {
	data := []byte("PASSWORD_ENABLED=true\n")
	for _, h := range detectAssignments("app/config.env", data) {
		if h.generic != nil && h.generic.slug == "weak-hardcoded-password" {
			t.Errorf("boolean flag must not be flagged as a weak password, got: %+v", h)
		}
	}
}

// TestIsWeakPasswordKey checks the key-shape helper directly, including the
// PASSWORD_MIN_LENGTH case the brief specifically calls out: secretKeyRe would
// match it (it contains "password"), but weakKeyRe must not, since the key
// does not *end* in a password/secret word.
func TestIsWeakPasswordKey(t *testing.T) {
	accept := []string{"password", "PASSWORD", "DB_PASSWORD", "db_pwd", "APP_SECRET", "passphrase", "PASS"}
	reject := []string{"PASSWORD_MIN_LENGTH", "PASSWORD_ENABLED", "DB_HOST", "SECRET_KEY", "API_KEY", "token"}
	for _, k := range accept {
		if !isWeakPasswordKey(k) {
			t.Errorf("isWeakPasswordKey(%q) = false, want true", k)
		}
	}
	for _, k := range reject {
		if isWeakPasswordKey(k) {
			t.Errorf("isWeakPasswordKey(%q) = true, want false", k)
		}
	}
}

// TestPlausibleWeakPassword checks the value-shape helper directly: it must
// reject pure numbers and booleans, and enforce the 5..64 length band.
func TestPlausibleWeakPassword(t *testing.T) {
	accept := []string{"hunter2", "changeme123", "qwerty", "P@ssw0rd"}
	reject := []string{"12", "1234567890", "true", "false", "yes", "no", "on", "off", "none", "null", "disabled", "enabled", "abcd", ""}
	for _, v := range accept {
		if !plausibleWeakPassword(v) {
			t.Errorf("plausibleWeakPassword(%q) = false, want true", v)
		}
	}
	for _, v := range reject {
		if plausibleWeakPassword(v) {
			t.Errorf("plausibleWeakPassword(%q) = true, want false", v)
		}
	}
	long := make([]byte, 65)
	for i := range long {
		long[i] = 'a'
	}
	if plausibleWeakPassword(string(long)) {
		t.Errorf("plausibleWeakPassword(65-char value) = true, want false (over length cap)")
	}
}

// TestDetectWeakPasswordEndToEnd exercises the full scanner (not just the
// bare detector) on the exact bake-off fixture, confirming the finding
// surfaces through Scanner.ScanText with the expected code and file scope.
func TestDetectWeakPasswordEndToEnd(t *testing.T) {
	s := New()
	ctx := context.Background()

	if got := codeSet(s.ScanText(ctx, "app/config.env", []byte("DB_PASSWORD=hunter2\n"), SourceFile)); got["DS-RAT-SEC-050"].Code == "" {
		t.Errorf("DB_PASSWORD=hunter2 in a config file must be flagged as DS-RAT-SEC-050")
	}
	if got := codeSet(s.ScanText(ctx, "app/main.py", []byte(`password = "hunter2"`), SourceFile)); got["DS-RAT-SEC-050"].Code != "" {
		t.Errorf("weak password in source code must not be flagged as DS-RAT-SEC-050")
	}
}

// TestIsPlaceholderHardened locks in the non-secret structural families that
// recur endlessly in vendored web assets and lockfiles: data URIs,
// subresource-integrity/checksum prefixes, bare MIME types, and AWS's own
// documented example credentials. None of these are ever real secrets.
func TestIsPlaceholderHardened(t *testing.T) {
	yes := []string{
		"data:image/png;base64,iVBORw0KGgo",                   // data URI
		"sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", // SRI hash
		"sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // SRI hash, realistic length
		"sha1-abcabcabcabcabcabc",                             // SRI hash, sha1, realistic length
		"image/png",                                           // MIME type
		"your_api_key_here",                                   // template
		"AKIAIOSFODNN7EXAMPLE",                                // AWS's documented example key
		"integrity=sha384-oqVuAfXRKap7fdgc",                   // SRI attribute (16-char digest)
		"application/json",                                    // bare MIME type
	}
	for _, v := range yes {
		if !isPlaceholder(v) {
			t.Errorf("%q should be a placeholder", v)
		}
	}
	// A MIME type with parameters (charset, boundary, …) is a common
	// Content-Type header value, not a bare MIME string. It does not match
	// the bare-MIME structural check (mimeRe is anchored end-of-string on the
	// type/subtype alone) and carries none of the other markers, so it is
	// correctly NOT treated as a placeholder by this function.
	if isPlaceholder("text/html; charset=utf-8") {
		t.Errorf("%q (MIME with parameters) should NOT be a placeholder", "text/html; charset=utf-8")
	}
	no := []string{
		"x9$Kp2!mQz7&Wd4cV0nT",
		"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
		// FINDING 1 (task 10 review): the old sriRe (`^(integrity=)?sha\d{0,3}-`)
		// matched on prefix alone, so a real secret that merely starts with
		// "sha-" was wrongly suppressed as a placeholder.
		"sha-my-actual-password-123",
		// FINDING 1: the old mimeRe (`[a-z0-9.+-]{1,30}` subtype) matched any
		// namespace/token-shaped value, so a real secret shaped like a MIME
		// type was wrongly suppressed.
		"application/x-my-secret-token-here",
		"text/plain-actually-a-token",
	}
	for _, v := range no {
		if isPlaceholder(v) {
			t.Errorf("%q should NOT be a placeholder", v)
		}
	}
}

// TestIsPlaceholderAWSDocumentedCreds locks in FINDING 2 (task 10 review): the
// placeholders map used to carry two dead entries for AWS's documented example
// credentials — "akiaiosfodnn7example" (already covered by the "example"
// substring marker) and a truncated fragment of the secret key that could
// never exact-match the real 40-char value. Both entries were removed; this
// test proves the real, full-length AWS documented credentials still resolve
// as placeholders purely via the "example" marker.
func TestIsPlaceholderAWSDocumentedCreds(t *testing.T) {
	creds := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
	}
	for _, v := range creds {
		if !isPlaceholder(v) {
			t.Errorf("%q (AWS documented example credential) should be a placeholder", v)
		}
	}
}

// TestDetectXMLCredentials locks in DS-RAT-SEC-051: assignRe only sees `k=v` /
// `k: v`, so a credential carried as XML element content
// (`<password>value</password>`) — the classic Maven settings.xml / Tomcat
// server.xml / .NET web.config leak shape — must be caught by a dedicated XML
// branch in detectAssignments.
func TestDetectXMLCredentials(t *testing.T) {
	xml := []byte(`<server><username>deploy</username><password>k9#Qz7$mP2xW</password></server>`)
	hits := detectAssignments("conf/settings.xml", xml)
	found := false
	for _, h := range hits {
		if h.secret == "k9#Qz7$mP2xW" {
			found = true
			if h.generic == nil {
				t.Fatalf("xml password hit missing generic metadata: %+v", h)
			}
			if h.generic.code != "DS-RAT-SEC-051" {
				t.Errorf("code = %q, want DS-RAT-SEC-051", h.generic.code)
			}
			if h.generic.slug != "xml-config-credential" {
				t.Errorf("slug = %q, want xml-config-credential", h.generic.slug)
			}
			if h.generic.severity != engine.SeverityHigh {
				t.Errorf("severity = %v, want High", h.generic.severity)
			}
		}
	}
	if !found {
		t.Fatalf("xml password not found: %+v", hits)
	}
}

// TestXMLNonSecretTagIgnored confirms a non-secret-named XML tag (whose value
// merely happens to be high-entropy) is not flagged — the tag name must clear
// secretKeyRe just like the k=v path does.
func TestXMLNonSecretTagIgnored(t *testing.T) {
	xml := []byte(`<config><timeout>Zx9$Kp2!mQz7&amp;Wd4c</timeout></config>`)
	for _, h := range detectAssignments("conf/app.xml", xml) {
		if h.secret != "" {
			t.Fatalf("timeout tag must not match: %+v", h)
		}
	}
}

// TestDetectXMLCredentialsMavenSettings exercises a realistic Maven
// settings.xml <server> block with a nested password element — the exact
// leak shape this task targets, distinct from the minimal fixture above.
func TestDetectXMLCredentialsMavenSettings(t *testing.T) {
	xml := []byte(`<settings>
  <servers>
    <server>
      <id>internal-repo</id>
      <username>ci-deploy</username>
      <password>R7$mK2pQz9#Xw4Ln</password>
    </server>
  </servers>
</settings>`)
	hits := detectAssignments("conf/settings.xml", xml)
	found := false
	for _, h := range hits {
		if h.secret == "R7$mK2pQz9#Xw4Ln" {
			found = true
			if h.generic == nil || h.generic.code != "DS-RAT-SEC-051" {
				t.Errorf("maven settings.xml password: got %+v, want DS-RAT-SEC-051", h)
			}
		}
	}
	if !found {
		t.Fatalf("maven settings.xml password not found: %+v", hits)
	}
}

// TestXMLMismatchedTagsNoCrash guards against a malformed/mismatched
// open-close tag pair (e.g. truncated config, hand-edited XML) causing a
// panic. Go's stdlib regexp (RE2) has no backreferences, so xmlKVRe cannot
// require the closing tag to literally equal the opening one — it only
// checks that *some* well-formed closing tag follows. A mismatched closer
// (`<password>...</passwrd>`) therefore still matches; that is accepted,
// documented behavior, not a bug. The one thing this test locks in is that it
// never panics on malformed markup.
func TestXMLMismatchedTagsNoCrash(t *testing.T) {
	xml := []byte(`<server><password>K9#zQ7pM2xW4rT6y</passwrd></server>`)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("mismatched XML tags must not panic: %v", r)
		}
	}()
	_ = detectAssignments("conf/broken.xml", xml)
}

// TestXMLPlaceholderPasswordSuppressed confirms a <password> element whose
// value is an obvious placeholder is suppressed via isPlaceholder, exactly as
// the k=v path already does.
func TestXMLPlaceholderPasswordSuppressed(t *testing.T) {
	xml := []byte(`<server><password>changeme</password></server>`)
	for _, h := range detectAssignments("conf/settings.xml", xml) {
		if h.secret != "" {
			t.Errorf("placeholder XML password must be suppressed, got: %+v", h)
		}
	}
}

// TestXMLWeakPasswordNotCaught documents current, intentional behavior: the
// Task 8 weak-password path (DS-RAT-SEC-050) only fires from the k=v/k: v
// assignRe loop, so a low-entropy, human-chosen password carried in an XML
// tag (e.g. Tomcat server.xml `<password>hunter2</password>`) fails the
// entropy floor in the XML branch and is silently dropped rather than
// downgraded to a weak-password finding. This is a known gap, not a bug:
// extending DS-RAT-SEC-050 to the XML shape is left as future work.
func TestXMLWeakPasswordNotCaught(t *testing.T) {
	xml := []byte(`<server><password>hunter2</password></server>`)
	for _, h := range detectAssignments("conf/server.xml", xml) {
		if h.generic != nil && h.generic.code == "DS-RAT-SEC-050" {
			t.Errorf("XML weak password must not be flagged as DS-RAT-SEC-050 (future work), got: %+v", h)
		}
		if h.secret == "hunter2" {
			t.Errorf("low-entropy XML password must not surface as any hit under current XML branch: %+v", h)
		}
	}
}

// TestXMLNonSecretHighEntropyTitleIgnored is the HTML/document-shaped
// analogue of TestXMLNonSecretTagIgnored: a <title> tag is common in HTML and
// must never be treated as a credential container even when its content
// happens to look dense, since "title" never matches secretKeyRe.
func TestXMLNonSecretHighEntropyTitleIgnored(t *testing.T) {
	xml := []byte(`<html><head><title>Xk9$pQ7mZw2#rT4nB6y</title></head></html>`)
	for _, h := range detectAssignments("public/index.html", xml) {
		if h.secret != "" {
			t.Fatalf("title tag must not match: %+v", h)
		}
	}
}

// TestXMLProseValueNotFlagged is the regression test for the Task 11 review
// finding: xmlKVRe's value group must not match document prose. Help text
// like `<password>Must be 8+ characters, include a number.</password>` (a
// validation-rule description, not a credential) shares the <password> tag
// name with the real leak shape but is a multi-word sentence — the fixed
// regex's whitespace-free token class must reject it.
func TestXMLProseValueNotFlagged(t *testing.T) {
	xml := []byte(`<password>Must be 8+ characters, include a number.</password>`)
	for _, h := range detectAssignments("docs/help.xml", xml) {
		if h.generic != nil && h.generic.code == "DS-RAT-SEC-051" {
			t.Errorf("prose XML password value must not be flagged as DS-RAT-SEC-051, got: %+v", h)
		}
	}
}

// TestXMLSymbolRichPasswordStillFlagged confirms the widened value charset
// (`[^\s<>]` rather than assignRe's stricter token class) still admits a
// symbol-rich real password — the fix must not trade the prose false
// positive for a new false negative on credentials containing `#`/`$`, which
// are not in assignRe's `[A-Za-z0-9+/=_.\-]` charset.
func TestXMLSymbolRichPasswordStillFlagged(t *testing.T) {
	xml := []byte(`<server><password>k9#Qz7$mP2xW</password></server>`)
	hits := detectAssignments("conf/settings.xml", xml)
	found := false
	for _, h := range hits {
		if h.secret == "k9#Qz7$mP2xW" && h.generic != nil && h.generic.code == "DS-RAT-SEC-051" {
			found = true
		}
	}
	if !found {
		t.Fatalf("symbol-rich XML password not found: %+v", hits)
	}
}

// TestXMLInstructionalCamelCaseValueNotFlagged locks in the fix for a
// polish-lens false positive: a single camelCase/PascalCase word with no
// digits or symbols -- an instructional placeholder like
// "SetViaEnvironmentVariable" left in a settings.xml template ("don't
// hardcode this, set it via env") -- has no spaces, so it still matches
// xmlKVRe's whitespace-free value class, and plausibleSecretValue's mixed
// upper/lower shortcut previously passed it unconditionally. It must now be
// rejected (its entropy sits well below the 4.0 fallback: ~3.6-3.9 for these
// examples).
func TestXMLInstructionalCamelCaseValueNotFlagged(t *testing.T) {
	values := []string{
		"SetViaEnvironmentVariable",
		"UseEnvironmentVariableInstead",
		"ProvidedByCICDPipeline",
	}
	for _, val := range values {
		xml := []byte(`<server><password>` + val + `</password></server>`)
		for _, h := range detectAssignments("conf/settings.xml", xml) {
			if h.secret == val {
				t.Errorf("instructional XML value %q must not be flagged as DS-RAT-SEC-051, got: %+v", val, h)
			}
		}
	}
}

// TestXMLValueSurroundingWhitespaceTrimmed confirms a value with incidental
// leading/trailing whitespace inside the tags (common when XML is
// pretty-printed or hand-edited) is still captured, trimmed to the bare
// token, rather than rejected outright by the whitespace-free value class.
func TestXMLValueSurroundingWhitespaceTrimmed(t *testing.T) {
	xml := []byte(`<server><password> k9#Qz7$mP2xW </password></server>`)
	hits := detectAssignments("conf/settings.xml", xml)
	found := false
	for _, h := range hits {
		if h.secret == "k9#Qz7$mP2xW" && h.generic != nil && h.generic.code == "DS-RAT-SEC-051" {
			found = true
		}
	}
	if !found {
		t.Fatalf("whitespace-padded XML password not found (want trimmed match): %+v", hits)
	}
}
