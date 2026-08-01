package vuln

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStderr runs fn with os.Stderr redirected to a pipe and returns
// whatever it wrote. A goroutine drains the pipe so output larger than the OS
// pipe buffer never deadlocks.
func captureStderr(t *testing.T, fn func() int) (int, string) {
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
	code := fn()
	w.Close()
	os.Stderr = orig
	return code, <-done
}

// TestCommand_UsageStringsSayVuln is a regression test for the "db"→"vuln"
// rename: `dsecrat vuln update -h` and `dsecrat vuln info -h` must present as the
// "vuln" command, not a leftover "db" name from before the CLI rename.
func TestCommand_UsageStringsSayVuln(t *testing.T) {
	code, out := captureStderr(t, func() int { return Command([]string{"update", "-h"}) })
	if code != 2 {
		t.Fatalf("update -h exit = %d, want 2", code)
	}
	if !strings.Contains(out, "Usage of vuln update:") {
		t.Errorf("update -h output missing %q:\n%s", "Usage of vuln update:", out)
	}
	if strings.Contains(out, "db update") || strings.Contains(out, "Usage of db") {
		t.Errorf("update -h output still mentions the old \"db\" name:\n%s", out)
	}

	code, out = captureStderr(t, func() int { return Command([]string{"info", "-h"}) })
	if code != 2 {
		t.Fatalf("info -h exit = %d, want 2", code)
	}
	if !strings.Contains(out, "Usage of vuln info:") {
		t.Errorf("info -h output missing %q:\n%s", "Usage of vuln info:", out)
	}
	if strings.Contains(out, "db info") || strings.Contains(out, "Usage of db") {
		t.Errorf("info -h output still mentions the old \"db\" name:\n%s", out)
	}
}

// TestCommand_TopLevelErrorsSayVuln covers the dispatch-level error strings
// (no subcommand / unknown subcommand), which used to say "db:".
func TestCommand_TopLevelErrorsSayVuln(t *testing.T) {
	code, out := captureStderr(t, func() int { return Command(nil) })
	if code != 2 || !strings.Contains(out, "vuln: expected a subcommand") {
		t.Errorf("Command(nil) = %d %q, want exit 2 mentioning \"vuln: expected a subcommand\"", code, out)
	}

	code, out = captureStderr(t, func() int { return Command([]string{"bogus"}) })
	if code != 2 || !strings.Contains(out, `vuln: unknown subcommand "bogus"`) {
		t.Errorf("Command([bogus]) = %d %q, want exit 2 mentioning the unknown subcommand", code, out)
	}
}

// TestCmdUpdate_EmptyEcosystemsAfterTrimErrors is a regression test: a value
// like "--ecosystems ,"  must not be treated as "an ecosystem list was
// provided" just because the flag string itself is non-empty. Previously this
// slipped past validation, built a MultiFetcher with zero fetchers, and
// silently wrote a zero-advisory DB.
func TestCmdUpdate_EmptyEcosystemsAfterTrimErrors(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.json")
	code, errOut := captureStderr(t, func() int {
		return Command([]string{"update", "--ecosystems", ",", "--out", out})
	})
	if code != 2 {
		t.Fatalf("update --ecosystems , → exit %d, want 2", code)
	}
	if !strings.Contains(errOut, "provide --from") {
		t.Errorf("expected the missing-source error, got: %s", errOut)
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("update must not have written --out when validation failed")
	}
}

// TestCmdUpdate_ZeroAdvisories_WarnsAndStillWrites exercises --from pointed at
// a directory with no matching feed documents: Update succeeds with 0
// advisories (no --ecosystems tokens involved), and cmdUpdate must print a
// clear stderr warning rather than silently overwriting a good DB with an
// empty one.
func TestCmdUpdate_ZeroAdvisories_WarnsAndStillWrites(t *testing.T) {
	fromDir := t.TempDir() // empty: no *.json feed documents
	out := filepath.Join(t.TempDir(), "out.json")

	code, errOut := captureStderr(t, func() int {
		return Command([]string{"update", "--from", fromDir, "--out", out})
	})
	if code != 0 {
		t.Fatalf("update --from <empty dir> → exit %d, want 0:\n%s", code, errOut)
	}
	if !strings.Contains(strings.ToUpper(errOut), "WARNING") {
		t.Errorf("expected a WARNING about 0 advisories, got: %s", errOut)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("expected --out to be written anyway: %v", err)
	}
	if len(data) == 0 {
		t.Error("written DB file is empty")
	}
}

// TestCmdUpdate_AtomicWrite verifies the write goes through a temp file that
// is renamed into place: after a successful update, no leftover ".tmp" file
// remains and --out contains valid DB JSON.
func TestCmdUpdate_AtomicWrite(t *testing.T) {
	fromDir := t.TempDir()
	out := filepath.Join(t.TempDir(), "out.json")

	code, errOut := captureStderr(t, func() int {
		return Command([]string{"update", "--from", fromDir, "--out", out})
	})
	if code != 0 {
		t.Fatalf("update → exit %d:\n%s", code, errOut)
	}
	if _, err := os.Stat(out + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temp file %s.tmp should not exist after a successful update (err=%v)", out, err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("expected %s to exist: %v", out, err)
	}
}
