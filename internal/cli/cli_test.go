package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// capture runs Main(args) with os.Stdout redirected, returning the exit code
// and captured stdout. A goroutine drains the pipe so large output never
// deadlocks on the OS pipe buffer. This exercises the whole CLI wiring end to
// end (dispatch → engine → formatter).
func capture(t *testing.T, args ...string) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()
	orig := os.Stdout
	os.Stdout = w
	code := Main(args)
	w.Close()
	os.Stdout = orig
	return code, <-done
}

// captureStderr is capture's twin for os.Stderr: cmdWatch reports its
// heartbeat/delta lines there rather than on stdout, so tests that exercise
// watch need a stderr-side pipe instead.
func captureStderr(t *testing.T, args ...string) (int, string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		io.Copy(&buf, r)
		done <- buf.String()
	}()
	orig := os.Stderr
	os.Stderr = w
	code := Main(args)
	w.Close()
	os.Stderr = orig
	return code, <-done
}

// alpineFixture builds a minimal filesystem target (apk db + os-release) with
// a musl package, the same shape TestSBOMOverFilesystem uses, so the vuln
// module has a real OS component to match a synthetic advisory against.
func alpineFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	apk := filepath.Join(dir, "lib", "apk", "db")
	if err := os.MkdirAll(apk, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "etc", "os-release"), []byte("ID=alpine\nVERSION_ID=3.19\n"), 0o644)
	os.WriteFile(filepath.Join(apk, "installed"), []byte("P:musl\nV:1.2.4-r2\nA:x86_64\n\n"), 0o644)
	return dir
}

// syntheticVulnDB writes a tiny advisory DB (internal schema, not an OSV feed)
// with one advisory that covers the musl package alpineFixture installs. Its
// presence in scan/watch output is proof that the DB path actually reached the
// vuln module, since the embedded default DB has no such CVE.
func syntheticVulnDB(t *testing.T) string {
	t.Helper()
	dbJSON := `{
  "schema": 1,
  "built_at": "2026-01-01T00:00:00Z",
  "source": "test",
  "advisories": [
    {
      "id": "CVE-2099-9999",
      "ecosystem": "alpine",
      "package": "musl",
      "ranges": [{"introduced": "0", "fixed": "1.2.5-r0"}],
      "severity": "high"
    }
  ]
}`
	path := filepath.Join(t.TempDir(), "vulndb.json")
	if err := os.WriteFile(path, []byte(dbJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	// tests run from the package dir; the examples live at the repo root.
	p := filepath.Join("..", "..", rel)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("fixture %s not present: %v", rel, err)
	}
	return p
}

func TestMainDispatch(t *testing.T) {
	if code := Main(nil); code != 2 {
		t.Errorf("no args → %d, want 2", code)
	}
	if code := Main([]string{"definitely-not-a-command"}); code != 2 {
		t.Errorf("unknown command → %d, want 2", code)
	}
	if code, out := capture(t, "version"); code != 0 || !strings.Contains(out, "docker-security") {
		t.Errorf("version → %d %q", code, out)
	}
}

func TestModulesListsAllCapabilities(t *testing.T) {
	code, out := capture(t, "modules")
	if code != 0 {
		t.Fatalf("modules exit = %d", code)
	}
	for _, want := range []string{"dockerfile", "sbom", "vuln", "secrets", "policy", "runtime", "harden", "netpolicy"} {
		if !strings.Contains(out, want) {
			t.Errorf("modules output missing %q", want)
		}
	}
}

func TestScanDockerfileGating(t *testing.T) {
	bad := repoFile(t, "examples/Dockerfile.bad")
	// No gate: a scan with findings still exits 0.
	if code, out := capture(t, "scan", bad); code != 0 {
		t.Errorf("scan (no gate) → %d\n%s", code, out)
	}
	// Gate at HIGH: Dockerfile.bad has HIGH findings → non-zero exit (CI gate).
	if code, _ := capture(t, "scan", "--fail-on", "high", bad); code != 1 {
		t.Errorf("scan --fail-on high on bad Dockerfile → %d, want 1", code)
	}
	// JSON format is selectable and contains a rule id.
	code, out := capture(t, "scan", "--format", "json", "--modules", "dockerfile", bad)
	if code != 0 || !strings.Contains(out, "DS-RAT-DF-") {
		t.Errorf("scan json → %d, missing DS-RAT-DF- rule:\n%s", code, out)
	}
}

func TestScanGoodDockerfilePassesGate(t *testing.T) {
	good := repoFile(t, "examples/Dockerfile.good")
	if code, _ := capture(t, "scan", "--fail-on", "high", good); code != 0 {
		t.Errorf("good Dockerfile should pass a HIGH gate, got non-zero")
	}
}

func TestSBOMOverFilesystem(t *testing.T) {
	// A directory with an apk DB is a filesystem SBOM target.
	dir := t.TempDir()
	apk := filepath.Join(dir, "lib", "apk", "db")
	if err := os.MkdirAll(apk, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "etc", "os-release"), nil, 0o644)
	os.MkdirAll(filepath.Join(dir, "etc"), 0o755)
	os.WriteFile(filepath.Join(dir, "etc", "os-release"), []byte("ID=alpine\nVERSION_ID=3.19\n"), 0o644)
	os.WriteFile(filepath.Join(apk, "installed"), []byte("P:musl\nV:1.2.4-r2\nA:x86_64\n\n"), 0o644)

	code, out := capture(t, "sbom", "--type", "filesystem", "--format", "cyclonedx", dir)
	if code != 0 {
		t.Fatalf("sbom exit = %d\n%s", code, out)
	}
	if !strings.Contains(out, "CycloneDX") || !strings.Contains(out, "pkg:apk/") {
		t.Errorf("sbom output not a CycloneDX doc with an apk purl:\n%s", out[:min(len(out), 400)])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestResolveVulnDB_FlagWins(t *testing.T) {
	t.Setenv("DSECRAT_VULN_DB", "/env/db.json")
	if got := resolveVulnDB("/flag/db.json"); got != "/flag/db.json" {
		t.Fatalf("flag should win, got %q", got)
	}
}

func TestResolveVulnDB_EnvSecond(t *testing.T) {
	t.Setenv("DSECRAT_VULN_DB", "/env/db.json")
	if got := resolveVulnDB(""); got != "/env/db.json" {
		t.Fatalf("env should win over default, got %q", got)
	}
}

func TestResolveVulnDB_DefaultPathOnlyIfExists(t *testing.T) {
	t.Setenv("DSECRAT_VULN_DB", "")
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if got := resolveVulnDB(""); got != "" {
		t.Fatalf("missing default file must yield empty, got %q", got)
	}
	dbPath := filepath.Join(dir, ".dsecrat", "vulndb.json")
	os.MkdirAll(filepath.Dir(dbPath), 0o755)
	os.WriteFile(dbPath, []byte("{}"), 0o644)
	if got := resolveVulnDB(""); got != dbPath {
		t.Fatalf("existing default file must be used, got %q", got)
	}
}

// TestScanVulnDBFlagAppliesToTarget is a regression test for cmdScan's
// `target.Metadata["vuln.db"] = p` line: it drives the real "scan" command
// end to end and asserts the flag's DB path is what the vuln module actually
// loads, not just accepted and ignored.
func TestScanVulnDBFlagAppliesToTarget(t *testing.T) {
	dir := alpineFixture(t)
	dbPath := syntheticVulnDB(t)

	// Baseline: the embedded default DB has no advisory for our synthetic CVE.
	code, out := capture(t, "scan", "--format", "json", "--modules", "vuln", dir)
	if code != 0 {
		t.Fatalf("scan (embedded db) → %d\n%s", code, out)
	}
	if strings.Contains(out, "CVE-2099-9999") {
		t.Fatalf("synthetic CVE unexpectedly present without --vuln-db:\n%s", out)
	}

	// --vuln-db must propagate through target.Metadata to the vuln module.
	code, out = capture(t, "scan", "--format", "json", "--modules", "vuln", "--vuln-db", dbPath, dir)
	if code != 0 {
		t.Fatalf("scan --vuln-db → %d\n%s", code, out)
	}
	if !strings.Contains(out, "CVE-2099-9999") {
		t.Errorf("scan --vuln-db %s did not use the custom advisory db:\n%s", dbPath, out)
	}
}

// TestWatchVulnDBFlagAppliesToTarget is cmdWatch's counterpart to the scan
// test above. `--count 1` bounds watch to a single, immediate cycle so the
// test never touches the ticker/interval machinery or blocks; the cycle's
// findings are reported on stderr rather than stdout.
func TestWatchVulnDBFlagAppliesToTarget(t *testing.T) {
	dir := alpineFixture(t)
	dbPath := syntheticVulnDB(t)

	code, errOut := captureStderr(t, "watch", "--count", "1", "--modules", "vuln", "--vuln-db", dbPath, dir)
	if code != 0 {
		t.Fatalf("watch --count 1 --vuln-db → %d\n%s", code, errOut)
	}
	if !strings.Contains(errOut, "CVE-2099-9999") {
		t.Errorf("watch --vuln-db %s did not surface the custom advisory:\n%s", dbPath, errOut)
	}
}

// TestScanVulnNowFlagAppliesToTarget is a regression test for the dead
// "vuln.now" metadata key: the vuln module read Target.Metadata["vuln.now"]
// but nothing ever set it, so DS-RAT-VULN-EOL always fell back to the wall
// clock. --vuln-now must pin that clock end to end through the scan command.
func TestScanVulnNowFlagAppliesToTarget(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// alpine 3.16 EOL is 2024-05-23 (internal/vulndb/eol.go).
	if err := os.WriteFile(filepath.Join(dir, "etc", "os-release"), []byte("ID=alpine\nVERSION_ID=3.16.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Before the EOL date: DS-RAT-VULN-EOL must not fire.
	code, out := capture(t, "scan", "--format", "json", "--modules", "vuln", "--vuln-now", "2024-01-01T00:00:00Z", dir)
	if code != 0 {
		t.Fatalf("scan --vuln-now (before EOL) → %d\n%s", code, out)
	}
	if strings.Contains(out, "DS-RAT-VULN-EOL") {
		t.Errorf("scan --vuln-now 2024-01-01 must not flag EOL for alpine 3.16 (EOL 2024-05-23):\n%s", out)
	}

	// After the EOL date: DS-RAT-VULN-EOL must fire.
	code, out = capture(t, "scan", "--format", "json", "--modules", "vuln", "--vuln-now", "2026-01-01T00:00:00Z", dir)
	if code != 0 {
		t.Fatalf("scan --vuln-now (after EOL) → %d\n%s", code, out)
	}
	if !strings.Contains(out, "DS-RAT-VULN-EOL") {
		t.Errorf("scan --vuln-now 2026-01-01 must flag EOL for alpine 3.16 (EOL 2024-05-23):\n%s", out)
	}

	// An invalid --vuln-now value must be rejected up front (exit 2), not
	// silently ignored.
	if code, errOut := captureStderr(t, "scan", "--vuln-now", "not-a-timestamp", dir); code != 2 {
		t.Errorf("scan --vuln-now not-a-timestamp → %d, want 2:\n%s", code, errOut)
	}
}

func TestComplianceCommand(t *testing.T) {
	// packs: lists loaded control packs.
	code, out := capture(t, "compliance", "packs")
	if code != 0 || !strings.Contains(out, "cis-docker") || !strings.Contains(out, "nist-ssdf") {
		t.Fatalf("compliance packs → %d\n%s", code, out)
	}

	// scan over a filesystem target: an alpine tree exercises sbom/vuln/secrets.
	dir := t.TempDir()
	apk := filepath.Join(dir, "lib", "apk", "db")
	os.MkdirAll(apk, 0o755)
	os.MkdirAll(filepath.Join(dir, "etc"), 0o755)
	os.WriteFile(filepath.Join(dir, "etc", "os-release"), []byte("ID=alpine\nVERSION_ID=3.19\n"), 0o644)
	os.WriteFile(filepath.Join(apk, "installed"), []byte("P:musl\nV:1.2.4-r2\nA:x86_64\n\n"), 0o644)

	code, out = capture(t, "compliance", "scan", "--type", "filesystem", dir)
	if code != 0 {
		t.Fatalf("compliance scan → %d\n%s", code, out)
	}
	if !strings.Contains(out, "COVERAGE") || !strings.Contains(out, "nist-ssdf") {
		t.Errorf("compliance scan output missing coverage table:\n%s", out)
	}

	// report --format oscal is machine-consumable.
	code, out = capture(t, "compliance", "report", "--type", "filesystem", "--format", "oscal", dir)
	if code != 0 || !strings.Contains(out, "assessment-results") {
		t.Errorf("compliance report oscal → %d\n%s", code, out[:min(len(out), 300)])
	}
}
