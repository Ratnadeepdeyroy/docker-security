package secrets

import (
	"bytes"
	"strings"
	"testing"
)

func TestHoneytokenCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := command([]string{"honeytoken", "--label", "prod", "--count", "2"}, &out, &errb); code != 0 {
		t.Fatalf("exit code = %d, stderr=%s", code, errb.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 honeytokens, got %d: %q", len(lines), out.String())
	}
	for _, ln := range lines {
		cols := strings.Split(ln, "\t")
		if len(cols) != 3 || !strings.HasPrefix(cols[1], "AKIA") {
			t.Errorf("malformed honeytoken line: %q", ln)
		}
	}
	// Determinism: same invocation yields the same output.
	var out2 bytes.Buffer
	command([]string{"honeytoken", "--label", "prod", "--count", "2"}, &out2, &errb)
	if out.String() != out2.String() {
		t.Error("honeytoken command output is not deterministic")
	}
}

func TestCommandUsageErrors(t *testing.T) {
	var out, errb bytes.Buffer
	if code := command(nil, &out, &errb); code != 2 {
		t.Errorf("no args exit = %d, want 2", code)
	}
	if code := command([]string{"bogus"}, &out, &errb); code != 2 {
		t.Errorf("unknown subcommand exit = %d, want 2", code)
	}
	if code := command([]string{"honeytoken"}, &out, &errb); code != 2 {
		t.Errorf("missing --label exit = %d, want 2", code)
	}
}
