package policy

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/policy"
)

// capture runs fn with os.Stdout redirected, returning what it wrote plus the
// exit code. It lets a test assert on real command output and CI exit behavior.
func capture(t *testing.T, fn func() int) (string, int) {
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
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String(), code
}

func policyFile() string { return filepath.Join("testdata", "gate.policy.json") }
func reportFile() string { return filepath.Join("testdata", "report.json") }

func TestEvalCommandDeniesAndExitsNonZero(t *testing.T) {
	out, code := capture(t, func() int {
		return EvalCommand([]string{"--policy", policyFile(), "--report", reportFile(), "--signed", "false"})
	})
	if code != 1 {
		t.Fatalf("exit code = %d, want 1 (deny)", code)
	}
	if !strings.Contains(out, "Decision: DENY") {
		t.Fatalf("output missing DENY decision:\n%s", out)
	}
	if !strings.Contains(out, "no-critical-cves") {
		t.Fatalf("output missing the critical-CVE denial:\n%s", out)
	}
}

func TestEvalCommandAllowsCleanSignedImage(t *testing.T) {
	// No report (no findings) + signed => allow => exit 0.
	out, code := capture(t, func() int {
		return EvalCommand([]string{"--policy", policyFile(), "--signed", "true"})
	})
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (allow)\n%s", code, out)
	}
	if !strings.Contains(out, "Decision: ALLOW") {
		t.Fatalf("output missing ALLOW decision:\n%s", out)
	}
}

func TestEvalCommandJSONExplain(t *testing.T) {
	out, code := capture(t, func() int {
		return EvalCommand([]string{"--policy", policyFile(), "--report", reportFile(), "--signed", "false", "--format", "json", "--explain"})
	})
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	var payload struct {
		Result      policy.Result      `json:"result"`
		Explanation policy.Explanation `json:"explanation"`
	}
	if err := json.Unmarshal([]byte(out), &payload); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, out)
	}
	if payload.Result.Decision != policy.DecisionDeny {
		t.Fatalf("decision = %s, want deny", payload.Result.Decision)
	}
	if len(payload.Explanation.Remediation) == 0 {
		t.Fatal("explanation missing remediation")
	}
}

func TestEvalCommandFailOnNever(t *testing.T) {
	_, code := capture(t, func() int {
		return EvalCommand([]string{"--policy", policyFile(), "--report", reportFile(), "--signed", "false", "--fail-on", "never"})
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0 with --fail-on never", code)
	}
}

func TestEvalCommandMissingPolicy(t *testing.T) {
	if code := EvalCommand([]string{"--report", reportFile()}); code != 2 {
		t.Fatalf("exit = %d, want 2 (usage) when --policy missing", code)
	}
}

func TestTestCommandRunsSuite(t *testing.T) {
	out, code := capture(t, func() int {
		return TestCommand([]string{filepath.Join("testdata", "gate.policytest.json")})
	})
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (suite passes)\n%s", code, out)
	}
	if !strings.Contains(out, "2 passed, 0 failed") {
		t.Fatalf("unexpected suite output:\n%s", out)
	}
}

func TestGateMapping(t *testing.T) {
	cases := []struct {
		d      policy.DecisionType
		failOn string
		want   bool
	}{
		{policy.DecisionDeny, "deny", true},
		{policy.DecisionWarn, "deny", false},
		{policy.DecisionWarn, "warn", true},
		{policy.DecisionDeny, "never", false},
		{policy.DecisionAllow, "warn", false},
	}
	for _, c := range cases {
		if got := gate(c.d, c.failOn); got != c.want {
			t.Errorf("gate(%s, %s) = %v, want %v", c.d, c.failOn, got, c.want)
		}
	}
}

// ExampleEvalCommand runs the CI gate exactly as `dsecrat policy eval` would and
// pins its human output, so the gate's behavior is documented and verified.
func ExampleEvalCommand() {
	EvalCommand([]string{
		"--policy", filepath.Join("testdata", "gate.policy.json"),
		"--report", filepath.Join("testdata", "report.json"),
		"--signed", "false",
	})
	// Output:
	// Policy: ci-gate (mode enforce)
	// Decision: DENY
	//
	// Denials:
	//   [HIGH]      require-signature  image is not signed by a trusted key
	//   [CRITICAL]  no-critical-cves   image has critical CVEs
	//
	// Warnings:
	//   [MEDIUM]  restricted-license  package under a restricted license
}

func TestCommandDispatch(t *testing.T) {
	if code := Command(nil); code != 2 {
		t.Errorf("Command(nil) = %d, want 2", code)
	}
	if code := Command([]string{"bogus"}); code != 2 {
		t.Errorf("Command(bogus) = %d, want 2", code)
	}
}
