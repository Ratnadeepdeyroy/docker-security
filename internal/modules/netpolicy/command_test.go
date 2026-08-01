package netpolicy

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns whatever
// it wrote, so we can assert on the command's rendered output.
func captureStdout(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	code := fn()
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out), code
}

func fixturePath(name string) string { return filepath.Join("testdata", name) }

func TestCommandReport(t *testing.T) {
	out, code := captureStdout(t, func() int {
		return Command([]string{fixturePath("capture_threats.json")})
	})
	if code != 0 {
		t.Fatalf("report exit = %d, want 0", code)
	}
	for _, want := range []string{"IMDS", "beacon", "anomaly(ies)"} {
		if !strings.Contains(strings.ToLower(out), strings.ToLower(want)) {
			t.Errorf("report output missing %q\n%s", want, out)
		}
	}
}

func TestCommandFailOn(t *testing.T) {
	_, code := captureStdout(t, func() int {
		return Command([]string{"--fail-on", "HIGH", fixturePath("capture_threats.json")})
	})
	if code != 1 {
		t.Errorf("--fail-on HIGH over a capture with critical findings should exit 1, got %d", code)
	}
	// A clean-ish baseline (no HIGH+) must not trip the gate.
	_, code = captureStdout(t, func() int {
		return Command([]string{"--fail-on", "CRITICAL", fixturePath("capture_baseline.json")})
	})
	if code != 0 {
		t.Errorf("baseline with no critical findings should exit 0, got %d", code)
	}
}

func TestCommandGenerateProducesYAML(t *testing.T) {
	out, code := captureStdout(t, func() int {
		return Command([]string{"--gen", "policy", "--workload", "shop/checkout", "--namespace", "shop", fixturePath("capture_baseline.json")})
	})
	if code != 0 {
		t.Fatalf("gen exit = %d, want 0", code)
	}
	for _, want := range []string{"kind: NetworkPolicy", "namespace: shop", "policyTypes:", "- Egress", "ipBlock:"} {
		if !strings.Contains(out, want) {
			t.Errorf("generated policy missing %q\n%s", want, out)
		}
	}

	// The FQDN allowlist form must name the allowed domain.
	out, code = captureStdout(t, func() int {
		return Command([]string{"--gen", "fqdn", "--workload", "shop/checkout", fixturePath("capture_baseline.json")})
	})
	if code != 0 || !strings.Contains(out, "api.stripe.com") {
		t.Errorf("fqdn gen exit=%d, output=%s", code, out)
	}

	// The default-deny form must render an egress-typed policy with no rules.
	out, _ = captureStdout(t, func() int {
		return Command([]string{"--gen", "deny", "--workload", "shop/checkout", fixturePath("capture_baseline.json")})
	})
	if !strings.Contains(out, "default-deny-egress") || !strings.Contains(out, "denies all egress") {
		t.Errorf("default-deny gen output unexpected:\n%s", out)
	}
}

func TestCommandDryRunAndDiff(t *testing.T) {
	dir := t.TempDir()
	// A candidate allowlist that permits DNS + the internal DB only.
	allow := filepath.Join(dir, "allow.json")
	if err := os.WriteFile(allow, []byte(`{"cidrs":["10.9.0.20/32"],"allow_dns":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := captureStdout(t, func() int {
		return Command([]string{"--dry-run", allow, fixturePath("capture_baseline.json")})
	})
	if code != 0 {
		t.Fatalf("dry-run exit = %d", code)
	}
	// api.stripe.com and the tor IP are not on the candidate list -> denied.
	if !strings.Contains(out, "would be denied") || !strings.Contains(out, "api.stripe.com") {
		t.Errorf("dry-run should report denied dests:\n%s", out)
	}

	// Diff a current (empty) allowlist against the generated one.
	current := filepath.Join(dir, "current.json")
	if err := os.WriteFile(current, []byte(`{"allow_dns":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code = captureStdout(t, func() int {
		return Command([]string{"--diff", current, "--workload", "shop/checkout", fixturePath("capture_baseline.json")})
	})
	if code != 0 || !strings.Contains(out, "+ allow fqdn api.stripe.com") {
		t.Errorf("diff exit=%d output=%s", code, out)
	}
}

func TestCommandUsageErrors(t *testing.T) {
	// No positional arg is a usage error.
	if code := Command([]string{}); code != 2 {
		t.Errorf("missing capture arg should exit 2, got %d", code)
	}
	// --diff without --workload is a usage error.
	_, code := captureStdout(t, func() int {
		return Command([]string{"--diff", "x.json", fixturePath("capture_baseline.json")})
	})
	if code != 2 {
		t.Errorf("--diff without --workload should exit 2, got %d", code)
	}
}
