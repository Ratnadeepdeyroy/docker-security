package runtime

import "sort"

// This file turns detection data into prevention: from a learned behavioral
// Baseline it generates a least-privilege seccomp profile in the standard
// OCI/Docker format, ready to hand to Phase 7 (hardening) to enforce. This is
// the "detection becomes prevention automatically" AI-age feature — the sensor
// watches a workload's real syscall usage and writes the allowlist for you,
// instead of an operator guessing. It is a pure function of the baseline (no
// clock, no model), so the same capture always yields the same profile.
//
// Generation is opt-in: nothing produces a profile unless a caller explicitly
// asks (the daemon's --learn-profile / the module's opt-in metadata).

// SeccompProfile is the subset of the OCI seccomp schema we emit. It marshals to
// a profile `docker run --security-opt seccomp=<file>` or a Kubernetes
// seccompProfile localhost file accepts directly.
type SeccompProfile struct {
	DefaultAction string        `json:"defaultAction"`
	Architectures []string      `json:"architectures"`
	Syscalls      []SeccompRule `json:"syscalls"`
	// Meta records provenance so a reviewer knows this profile was machine-
	// generated from observed behavior, and from which rule pack.
	Meta SeccompMeta `json:"_meta"`
}

// SeccompRule allows (or otherwise acts on) a set of syscalls.
type SeccompRule struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

// SeccompMeta is non-standard provenance metadata (underscore-prefixed so tools
// ignore it) describing how the profile was produced.
type SeccompMeta struct {
	GeneratedBy string `json:"generated_by"`
	RuleSet     string `json:"ruleset"`
	Image       string `json:"image"`
	Observed    int    `json:"observed_syscalls"`
}

// baselineSyscalls are syscalls virtually every process needs. Including them
// keeps a generated profile from instantly killing the workload it protects — a
// learned profile that forgets `exit` or `mmap` is worse than none. This is a
// conservative floor; everything above it comes from observed behavior.
var baselineSyscalls = []string{
	"read", "write", "close", "fstat", "mmap", "mprotect", "munmap", "brk",
	"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "exit", "exit_group",
	"nanosleep", "clock_gettime", "gettimeofday", "getpid", "getppid",
	"futex", "sched_yield", "arch_prctl", "set_tid_address", "set_robust_list",
	"prlimit64", "getrandom", "epoll_create1", "epoll_ctl", "epoll_pwait",
}

// GenerateSeccompProfile builds a least-privilege profile for one workload from a
// baseline: default-deny, allow the observed syscalls plus the safety floor. It
// returns nil if the workload is unknown in the baseline. Architectures cover
// the two we build for (x86-64 and arm64) plus their 32-bit compat entries.
func GenerateSeccompProfile(b *Baseline, workloadKey string) *SeccompProfile {
	if b == nil {
		return nil
	}
	wp := b.Workloads[workloadKey]
	if wp == nil {
		return nil
	}
	allow := map[string]struct{}{}
	for _, s := range baselineSyscalls {
		allow[s] = struct{}{}
	}
	for _, s := range wp.Syscalls {
		allow[s] = struct{}{}
	}
	names := make([]string, 0, len(allow))
	for s := range allow {
		names = append(names, s)
	}
	sort.Strings(names) // deterministic output

	return &SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"},
		Syscalls:      []SeccompRule{{Names: names, Action: "SCMP_ACT_ALLOW"}},
		Meta: SeccompMeta{
			GeneratedBy: "dsecrat-runtime profile generator",
			RuleSet:     RuleSetVersion,
			Image:       wp.Image,
			Observed:    len(wp.Syscalls),
		},
	}
}
