package harden

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	hardenlib "github.com/Ratnadeepdeyroy/docker-security/internal/harden"
)

func TestCommandUsage(t *testing.T) {
	if Command(nil) != 2 {
		t.Errorf("no subcommand should return usage exit 2")
	}
	if Command([]string{"bogus"}) != 2 {
		t.Errorf("unknown subcommand should return usage exit 2")
	}
}

func TestCommandGenProfileSeccomp(t *testing.T) {
	out := filepath.Join(t.TempDir(), "web.seccomp.json")
	code := Command([]string{"gen-profile", "--from", "testdata/observation.json", "--type", "seccomp", "--out", out})
	if code != 0 {
		t.Fatalf("gen-profile seccomp exit = %d, want 0", code)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var p hardenlib.SeccompProfile
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatalf("generated profile is not valid JSON: %v", err)
	}
	if p.DefaultAction != hardenlib.ActErrno {
		t.Errorf("enforce profile default action = %q, want SCMP_ACT_ERRNO", p.DefaultAction)
	}
	// A syscall from the observation must be allowed; a dangerous unobserved one denied.
	if !p.Allows("connect") {
		t.Errorf("observed syscall connect must be allowed")
	}
	if p.Allows("ptrace") {
		t.Errorf("unobserved ptrace must be denied")
	}
}

func TestCommandGenProfileAppArmor(t *testing.T) {
	out := filepath.Join(t.TempDir(), "web.apparmor")
	code := Command([]string{"gen-profile", "--from", "testdata/observation.json", "--type", "apparmor", "--name", "web", "--out", out})
	if code != 0 {
		t.Fatalf("gen-profile apparmor exit = %d, want 0", code)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(out) {
		t.Fatal("expected absolute temp path")
	}
	if len(data) == 0 || string(data[:8]) != "#include" {
		t.Errorf("generated AppArmor profile looks wrong:\n%s", data)
	}
}

func TestCommandGenProfileMissingFrom(t *testing.T) {
	if Command([]string{"gen-profile", "--type", "seccomp"}) != 2 {
		t.Errorf("missing --from should return usage exit 2")
	}
}

// silenceStdout redirects os.Stdout to /dev/null for the duration of a test so
// the verify command's report does not pollute test output.
func silenceStdout(t *testing.T) {
	t.Helper()
	orig := os.Stdout
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = devnull
	t.Cleanup(func() {
		os.Stdout = orig
		devnull.Close()
	})
}

func TestCommandVerifyFailOn(t *testing.T) {
	silenceStdout(t)
	// Without a gate, verification of a bad pod still exits 0. (Flags precede the
	// positional path, as Go's flag package stops parsing at the first non-flag.)
	if code := Command([]string{"verify", "--format", "json", "testdata/privileged.pod.json"}); code != 0 {
		t.Errorf("verify without --fail-on should exit 0, got %d", code)
	}
	// With a CRITICAL gate, the privileged pod (docker.sock is CRITICAL) exits 1.
	if code := Command([]string{"verify", "--format", "json", "--fail-on", "CRITICAL", "testdata/privileged.pod.json"}); code != 1 {
		t.Errorf("verify --fail-on CRITICAL should exit 1 on the privileged pod")
	}
	// The hardened OCI spec passes even a HIGH gate.
	if code := Command([]string{"verify", "--format", "json", "--fail-on", "HIGH", "testdata/hardened.oci.json"}); code != 0 {
		t.Errorf("verify --fail-on HIGH should exit 0 on the hardened spec")
	}
}

func TestCommandVerifyMissingArg(t *testing.T) {
	if Command([]string{"verify"}) != 2 {
		t.Errorf("verify without a path should return usage exit 2")
	}
}
