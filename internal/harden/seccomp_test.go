package harden

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// update rewrites golden files instead of comparing. Run:
//
//	go test ./internal/harden/ -run Golden -update
//
// then eyeball the diff — a golden is a reviewed baseline, not whatever the code
// happens to emit today.
var update = flag.Bool("update", false, "rewrite golden files")

// sampleObservation is a small, realistic trace of a network service: it opens
// files, does socket I/O, and forks/execs a helper. Used across the generator
// tests so the allow-set assertions and the golden all describe one workload.
func sampleObservation() Observation {
	return Observation{
		Workload: "web",
		Syscalls: []string{
			"openat", "read", "write", "close", "socket", "connect", "accept4",
			"epoll_create1", "epoll_ctl", "epoll_wait", "clone", "execve",
			// duplicate + unsorted on purpose: generation must normalise.
			"read", "openat",
		},
		Capabilities: []string{"NET_BIND_SERVICE", "cap_setuid", "SETGID"},
		FileReads:    []string{"/etc/ssl/certs/**", "/app/config.yaml"},
		FileWrites:   []string{"/var/log/app/**", "/tmp/**"},
		FileExecs:    []string{"/app/server", "/usr/bin/helper"},
		Network:      true,
		Complete:     true,
	}
}

func TestGenerateSeccompCoversObservedDeniesRest(t *testing.T) {
	obs := sampleObservation()
	p := GenerateSeccomp(obs, SeccompOptions{Name: "web"})

	// Every observed syscall MUST be allowed — a generated profile that killed the
	// workload's own calls would be worse than useless.
	for _, sc := range obs.syscallSet() {
		if !p.Allows(sc) {
			t.Errorf("observed syscall %q is not allowed by the generated profile", sc)
		}
	}
	// The bootstrap minimum MUST be present so the process can start and exit.
	for _, sc := range []string{"exit_group", "rt_sigreturn", "mmap", "futex"} {
		if !p.Allows(sc) {
			t.Errorf("bootstrap syscall %q must be allowed", sc)
		}
	}
	// Dangerous syscalls the workload never used MUST be denied.
	for _, sc := range []string{"ptrace", "mount", "reboot", "init_module", "kexec_load"} {
		if p.Allows(sc) {
			t.Errorf("unobserved dangerous syscall %q must be denied", sc)
		}
	}
	// Enforce mode denies with EPERM.
	if p.DefaultAction != ActErrno {
		t.Errorf("enforce default action = %q, want %q", p.DefaultAction, ActErrno)
	}
	if p.DefaultErrnoRet == nil || *p.DefaultErrnoRet != 1 {
		t.Errorf("enforce default errno = %v, want 1 (EPERM)", p.DefaultErrnoRet)
	}
}

func TestGenerateSeccompAuditMode(t *testing.T) {
	p := GenerateSeccomp(sampleObservation(), SeccompOptions{AuditMode: true})
	if p.DefaultAction != ActLog {
		t.Errorf("audit default action = %q, want %q", p.DefaultAction, ActLog)
	}
	if p.DefaultErrnoRet != nil {
		t.Errorf("audit mode must not set defaultErrnoRet, got %v", *p.DefaultErrnoRet)
	}
	// In audit mode nothing is blocked: an unobserved call still "runs" (logged).
	if !p.Allows("ptrace") {
		t.Errorf("audit mode should allow-but-log unobserved calls")
	}
}

func TestGenerateSeccompDeterministic(t *testing.T) {
	a := GenerateSeccomp(sampleObservation(), SeccompOptions{Name: "web"})
	b := GenerateSeccomp(sampleObservation(), SeccompOptions{Name: "web"})
	aj, _ := a.JSON()
	bj, _ := b.JSON()
	if !bytes.Equal(aj, bj) {
		t.Errorf("seccomp generation is not deterministic")
	}
}

func TestDiffSeccompNewlyBlocked(t *testing.T) {
	// A broad prior profile (audit: allows everything it names) tightened to the
	// enforcing generated one should report ptrace as newly blocked.
	prior := &SeccompProfile{
		DefaultAction: ActErrno,
		Syscalls:      []SeccompRule{{Names: []string{"openat", "read", "write", "ptrace"}, Action: ActAllow}},
	}
	next := GenerateSeccomp(sampleObservation(), SeccompOptions{})
	d := DiffSeccomp(prior, next)
	if !contains(d.NewlyBlocked, "ptrace") {
		t.Errorf("expected ptrace in NewlyBlocked, got %v", d.NewlyBlocked)
	}
	if d.Empty() {
		t.Errorf("diff should not be empty")
	}
}

func TestSeccompGolden(t *testing.T) {
	p := GenerateSeccomp(sampleObservation(), SeccompOptions{Name: "web"})
	data, err := p.JSON()
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "web.seccomp.golden.json")
	if *update {
		if err := os.WriteFile(golden, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(want, data) {
		t.Errorf("seccomp golden mismatch; run `go test ./internal/harden/ -run Golden -update`")
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
