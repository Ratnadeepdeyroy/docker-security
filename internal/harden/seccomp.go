package harden

import (
	"encoding/json"
	"sort"
)

// --- Seccomp profile model (real OCI/Docker JSON format) ---------------------
//
// This is the on-disk schema runc, containerd and Docker all consume: a default
// action, a list of architectures, and rules mapping syscall-name sets to an
// action. We emit exactly that shape so a generated profile can be dropped into
// `--security-opt seccomp=profile.json` or a Kubernetes seccomp Localhost file
// with no translation. We deliberately keep our own bookkeeping out of the JSON
// so the format stays faithful to the kernel-facing schema.

// SeccompAction is a libseccomp action string as it appears in the profile JSON.
type SeccompAction string

const (
	// ActAllow lets the syscall run.
	ActAllow SeccompAction = "SCMP_ACT_ALLOW"
	// ActErrno fails the syscall with an errno (default-deny for a filter).
	ActErrno SeccompAction = "SCMP_ACT_ERRNO"
	// ActLog allows the syscall but logs it — the "audit/complain" mode used to
	// observe a workload before tightening to ActErrno.
	ActLog SeccompAction = "SCMP_ACT_LOG"
	// ActTrace traps to a tracer; treated as "runs" for allow-set purposes.
	ActTrace SeccompAction = "SCMP_ACT_TRACE"
	// ActKill kills the thread issuing the syscall.
	ActKill SeccompAction = "SCMP_ACT_KILL"
)

// SeccompRule maps a set of syscall names to an action. Args-based conditions
// exist in the schema but a least-privilege allow-list does not need them, so we
// emit name-only rules — simpler to review and impossible to get subtly wrong.
type SeccompRule struct {
	Names  []string      `json:"names"`
	Action SeccompAction `json:"action"`
}

// SeccompProfile is a complete seccomp profile in OCI/Docker JSON form.
type SeccompProfile struct {
	DefaultAction SeccompAction `json:"defaultAction"`
	// DefaultErrnoRet is the errno returned by a default ActErrno (1 = EPERM).
	// Pointer so it is omitted when the default action is not ActErrno.
	DefaultErrnoRet *uint         `json:"defaultErrnoRet,omitempty"`
	Architectures   []string      `json:"architectures,omitempty"`
	Syscalls        []SeccompRule `json:"syscalls,omitempty"`
}

// JSON renders the profile as indented, deterministic JSON ready to write to a
// file and hand to a runtime.
func (p *SeccompProfile) JSON() ([]byte, error) {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// EffectiveAction returns the action the profile applies to a syscall: the
// action of the first rule that names it, else the default action.
func (p *SeccompProfile) EffectiveAction(syscall string) SeccompAction {
	for _, r := range p.Syscalls {
		for _, n := range r.Names {
			if n == syscall {
				return r.Action
			}
		}
	}
	return p.DefaultAction
}

// Allows reports whether the syscall is permitted to execute under this profile.
// ActAllow and ActLog let the call run (Log merely audits it); everything else
// blocks it. This is what the allow-set test asserts: every syscall the workload
// needs must be allowed, and dangerous ones it never used must not be.
func (p *SeccompProfile) Allows(syscall string) bool {
	switch p.EffectiveAction(syscall) {
	case ActAllow, ActLog:
		return true
	default:
		return false
	}
}

// AllowedSyscalls returns every syscall the profile allows, sorted. Only
// meaningful for a default-deny profile (the shape this package generates).
func (p *SeccompProfile) AllowedSyscalls() []string {
	var out []string
	for _, r := range p.Syscalls {
		if r.Action == ActAllow || r.Action == ActLog {
			out = append(out, r.Names...)
		}
	}
	return dedupeSort(out)
}

// SeccompDiff is the result of comparing two profiles: what a switch from old to
// new would newly block or newly permit. It powers the "what this newly blocks"
// explanation in the profile-from-behaviour loop (bundle.go), so an operator or
// agent can see the blast radius before applying a tighter profile.
type SeccompDiff struct {
	// NewlyBlocked are syscalls old allowed that new denies.
	NewlyBlocked []string `json:"newly_blocked,omitempty"`
	// NewlyAllowed are syscalls old denied that new allows.
	NewlyAllowed []string `json:"newly_allowed,omitempty"`
}

// Empty reports whether the two profiles allow exactly the same syscalls.
func (d SeccompDiff) Empty() bool {
	return len(d.NewlyBlocked) == 0 && len(d.NewlyAllowed) == 0
}

// DiffSeccomp computes the allow-set delta from old to new over the union of the
// syscalls both profiles name. It compares allow-sets rather than raw rules, so
// two profiles that reach the same decision by different rule shapes diff clean.
func DiffSeccomp(old, new *SeccompProfile) SeccompDiff {
	names := map[string]bool{}
	for _, s := range old.namedSyscalls() {
		names[s] = true
	}
	for _, s := range new.namedSyscalls() {
		names[s] = true
	}
	var d SeccompDiff
	for s := range names {
		wasAllowed := old.Allows(s)
		nowAllowed := new.Allows(s)
		switch {
		case wasAllowed && !nowAllowed:
			d.NewlyBlocked = append(d.NewlyBlocked, s)
		case !wasAllowed && nowAllowed:
			d.NewlyAllowed = append(d.NewlyAllowed, s)
		}
	}
	sort.Strings(d.NewlyBlocked)
	sort.Strings(d.NewlyAllowed)
	return d
}

// namedSyscalls returns every syscall name mentioned by any rule in the profile.
func (p *SeccompProfile) namedSyscalls() []string {
	var out []string
	for _, r := range p.Syscalls {
		out = append(out, r.Names...)
	}
	return out
}
