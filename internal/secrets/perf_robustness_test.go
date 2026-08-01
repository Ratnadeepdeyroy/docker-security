package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// --- 1. Anchor prefilter (rules.go) -----------------------------------------
//
// The prefilter must never produce a false negative: every rule's anchor(s)
// are a necessary substring of anything its regex can match, so gating the
// full regex behind bytes.Contains cannot change which secrets are found.
// This table pins one canonical, well-known *fake* token per provider rule
// (covering all 37, including the ones with no clean anchor) and asserts each
// still fires.
func TestAnchorPrefilterPreservesAllProviderDetections(t *testing.T) {
	cases := []struct {
		slug string
		text string
	}{
		{"aws-access-key-id", "aws_access_key_id = " + "AKIAIOSFODNN7EXAMPLE"},
		{"aws-secret-access-key", `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`},
		{"gcp-service-account-key", `"private_key": "-----BEGIN PRIVATE KEY-----"`},
		{"github-token", "ghp_0123456789abcdef" + "ghijklmnopqrstuvwxyz"},
		{"github-fine-grained-pat", "github_pat_" + strings.Repeat("A", 22) + "_" + strings.Repeat("B", 59)},
		{"slack-token", "xoxb-" + strings.Repeat("a", 20)},
		{"private-key", "-----BEGIN RSA " + "PRIVATE KEY-----"},
		{"jwt", "eyJ" + strings.Repeat("A", 10) + ".eyJ" + strings.Repeat("B", 10) + "." + strings.Repeat("C", 10)},
		{"stripe-secret-key", "sk_live_" + strings.Repeat("a", 24)},
		{"google-api-key", "AIza" + strings.Repeat("A", 35)},
		{"sendgrid-api-key", "SG." + strings.Repeat("a", 22) + "." + strings.Repeat("b", 43)},
		{"npm-token", "npm_" + strings.Repeat("a", 36)},
		{"db-connection-uri", "db = postgres://admin:Tr0ub4" + "dor3xyz@db.internal:5432/app"},
		{"gitlab-pat", "token: glpat-AbC" + "dEfGhIjKlMnOpQrSt"},
		{"gitlab-pipeline-trigger", "glptt-0123456789abcdef0" + "123456789abcdef01234567"},
		{"digitalocean-token", "dop_v1_" + strings.Repeat("a1", 32)},
		// Split around the "T3BlbkFJ" marker so this test fixture is not a
		// contiguous OpenAI-key literal in the source (which trips secret
		// scanners); the runtime value is identical, so detection is unchanged.
		{"openai-api-key", "sk-proj-AbCdEfGhIjKlMnOpQrStT3Blbk" + "FJAbCdEfGhIjKlMnOpQrSt"},
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
	if len(cases) != len(providerRules) {
		t.Fatalf("test table has %d cases but there are %d provider rules — every rule must be covered", len(cases), len(providerRules))
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
			t.Errorf("%s: anchor prefilter caused a false negative — not detected in %q", c.slug, c.text)
		}
	}
}

// TestAnchorPrefilterSkipsUnanchoredContent confirms the prefilter is actually
// doing work: a large blob containing none of the provider anchors should
// trigger only the handful of rules with no clean literal anchor (the
// documented fallback case), not all 37.
func TestAnchorPrefilterSkipsUnanchoredContent(t *testing.T) {
	var b strings.Builder
	lorem := "the quick brown fox jumps over the lazy dog while ordinary configuration " +
		"values flow through unrelated business logic with no credential shape at all "
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&b, "%s line %d\n", lorem, i)
	}
	blob := []byte(b.String())

	providerRegexRuns = 0
	hits := applyProviderRules(blob, false)
	runs := providerRegexRuns

	if len(hits) != 0 {
		t.Fatalf("benign blob produced %d hits, want 0", len(hits))
	}
	if runs >= len(providerRules) {
		t.Errorf("anchor prefilter did not filter anything: %d regex runs out of %d rules", runs, len(providerRules))
	}
	// Only rules with no clean anchor (currently one: mailchimp-key) — plus any
	// false-positive substring collision from the fallback word-fragment
	// anchors (e.g. "pat") — should ever run their full regex here.
	if runs > 5 {
		t.Errorf("expected only a handful of fallback/collision regex runs on unanchored content, got %d", runs)
	}
}

// TestAnchorPrefilterCaseFoldRules confirms the case-insensitive-anchored
// rules (aws-secret-access-key, gcp-service-account-key, twilio, mailgun)
// still fire regardless of the case of the surrounding keyword text, since
// the anchor check itself must fold case exactly like the (?i) regex does.
func TestAnchorPrefilterCaseFoldRules(t *testing.T) {
	cases := []struct {
		slug string
		text string
	}{
		{"aws-secret-access-key", `AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`},
		{"gcp-service-account-key", `"PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----"`},
		{"twilio-api-key", "TWILIO_AUTH: SK01234567" + "89abcdef0123456789abcdef"},
		{"mailgun-key", "MAILGUN_API_KEY = key-01234" + "56789abcdef0123456789abcdef"},
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
			t.Errorf("%s: case-folded anchor missed a match in %q", c.slug, c.text)
		}
	}
}

// --- 2. contentHash (image.go) ----------------------------------------------

// TestContentHashMatchesDirectSHA256 pins contentHash's output format: a
// truncated hex-encoded SHA-256 of the raw bytes, with no string round-trip
// required to produce it (verified for byte sequences that are not valid
// UTF-8, which a []byte->string->[]byte path would otherwise be tempted to
// mangle).
func TestContentHashMatchesDirectSHA256(t *testing.T) {
	cases := [][]byte{
		[]byte("hello world"),
		{},
		{0xff, 0xfe, 0x00, 0x01, 0x80, 0x81}, // invalid UTF-8
		bytesRepeat(0x41, 10000),             // large, uniform
		append([]byte{0x7f, 'E', 'L', 'F'}, 0x00, 0x01, 0x02), // ELF-ish binary
	}
	for i, data := range cases {
		got := contentHash(data)
		sum := sha256.Sum256(data)
		want := hex.EncodeToString(sum[:])[:16]
		if got != want {
			t.Errorf("case %d: contentHash(%v) = %q, want %q", i, data, got, want)
		}
		if len(got) != 16 {
			t.Errorf("case %d: contentHash length = %d, want 16", i, len(got))
		}
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// --- 3. lineAt / newlineOffsets (secrets.go, scanner.go) --------------------

// TestLineAtMatchesLineOf property-tests the new O(log n) line lookup against
// the original O(offset) lineOf over a variety of offsets, including the
// file start, file end, past-end, and mid-file positions straddling newlines.
func TestLineAtMatchesLineOf(t *testing.T) {
	data := []byte("line one\nline two\nline three\n\nline five\nlast line with no trailing newline")
	newlines := newlineOffsets(data)

	offsets := []int{0, 1, 8, 9, 10, 18, 19, 29, 30, 31, len(data) / 2, len(data) - 1, len(data), len(data) + 5}
	for _, off := range offsets {
		want := lineOf(data, off)
		got := lineAt(newlines, len(data), off)
		if got != want {
			t.Errorf("offset %d: lineAt = %d, want %d (lineOf)", off, got, want)
		}
	}
}

// TestScanFileReportsCorrectLinesForMultipleHits exercises the precomputed
// newline table through the real scanning path: several distinct secrets
// spread across many lines must each report their own correct line number,
// not a value corrupted by sharing one newline table across hits.
func TestScanFileReportsCorrectLinesForMultipleHits(t *testing.T) {
	lines := make([]string, 0, 20)
	for i := 0; i < 20; i++ {
		lines = append(lines, fmt.Sprintf("filler line %d, nothing to see here", i))
	}
	// Insert known secrets at known 1-based line numbers.
	lines[4] = "github_token: ghp_0123456789abcdefghijklmnopqrstuvwxyz" // line 5
	lines[12] = "aws_key: AKIAIOSFODNN7EXAMPLE"                         // line 13
	content := strings.Join(lines, "\n")

	s := New()
	ds := s.ScanText(context.Background(), "multi.env", []byte(content), SourceFile)
	got := map[string]int{}
	for _, d := range ds {
		got[d.Code] = d.Line
	}
	if got["DS-RAT-SEC-004"] != 5 {
		t.Errorf("github token line = %d, want 5", got["DS-RAT-SEC-004"])
	}
	if got["DS-RAT-SEC-001"] != 13 {
		t.Errorf("aws key line = %d, want 13", got["DS-RAT-SEC-001"])
	}
}

// --- 4. ScanImage cancellation (image.go) -----------------------------------

// manyFileImage builds an image whose effective filesystem holds n files,
// each carrying a distinct, real provider secret, so a full scan produces
// exactly n detections and a canceled scan can be told apart from a complete
// one by counting them.
func manyFileImage(n int) *oci.Image {
	files := make([]*oci.File, 0, n)
	for i := 0; i < n; i++ {
		files = append(files, &oci.File{
			Path: fmt.Sprintf("app/secret-%03d.env", i),
			Data: []byte(fmt.Sprintf("github_token: ghp_%036d\n", i)),
		})
	}
	return &oci.Image{Layers: []*oci.Layer{{Index: 0, Digest: "sha256:base", Files: files}}}
}

func TestScanImageRespectsCancellationBetweenFiles(t *testing.T) {
	img := manyFileImage(200)
	s := New()

	full := s.ScanImage(context.Background(), img)
	if len(full) != 200 {
		t.Fatalf("uncancelled scan found %d detections, want 200", len(full))
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already canceled before ScanImage even starts its file loops
	partial := s.ScanImage(ctx, img)
	if len(partial) >= len(full) {
		t.Errorf("pre-canceled ScanImage found %d detections, want fewer than the complete scan's %d", len(partial), len(full))
	}
}

// --- 5. scanConfig warning surfacing (image.go) -----------------------------

func TestScanConfigSurfacesParseWarningOnMalformedJSON(t *testing.T) {
	s := New()
	img := &oci.Image{
		Config: []byte(`{"config": {"Env": ["A=1"]}, "history": [`), // truncated/invalid JSON
		Layers: []*oci.Layer{{Index: 0, Digest: "sha256:x", Files: []*oci.File{
			{Path: "a.env", Data: []byte("token: ghp_0123456789abcdefghijklmnopqrstuvwxyz\n")},
		}}},
	}

	// The legacy entry point must keep working exactly as before: detections
	// from the other passes are unaffected by a config parse failure.
	dets := s.ScanImage(context.Background(), img)
	if len(dets) == 0 {
		t.Fatalf("expected pass-1 detections despite a malformed image config")
	}

	// The new entry point must surface the parse failure instead of discarding
	// it silently.
	dets2, warnings := s.ScanImageDetailed(context.Background(), img)
	if len(dets2) != len(dets) {
		t.Errorf("ScanImageDetailed detections = %d, want %d (same as ScanImage)", len(dets2), len(dets))
	}
	if len(warnings) == 0 {
		t.Errorf("expected a warning for the unparsable image config, got none")
	}
}

func TestScanConfigNoWarningOnValidConfig(t *testing.T) {
	s := New()
	img := &oci.Image{
		Config: []byte(`{"config": {"Env": ["PATH=/usr/bin"]}, "history": []}`),
	}
	_, warnings := s.ScanImageDetailed(context.Background(), img)
	if len(warnings) != 0 {
		t.Errorf("valid config should produce no warnings, got %v", warnings)
	}
}
