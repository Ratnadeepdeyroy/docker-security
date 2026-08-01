package runtime

import (
	"path"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// This file holds container-escape and privilege-escalation rules — the highest
// stakes detections, because a successful escape turns a container compromise
// into a host compromise.

// --- DS-RAT-RT-003 container escape ------------------------------------------

type escapeRule struct{ ruleBase }

func newEscapeRule() Rule {
	return &escapeRule{ruleBase{
		id: "DS-RAT-RT-003",
		info: RuleInfo{
			Title:       "Container escape attempt",
			Severity:    engine.SeverityCritical,
			Technique:   techEscapeToHost,
			Default:     true,
			Description: "An action characteristic of breaking container isolation was observed: an escape tool executed (nsenter/unshare/runc), a namespace-manipulating syscall, or access to a host-escape path (docker.sock, /proc/1/root, cgroup release_agent).",
			Remediation: "Assume host compromise. Cordon and investigate the node. Remove privileged/hostPath mounts and the container runtime socket from workloads; drop CAP_SYS_ADMIN; enforce a restricted seccomp profile.",
		},
	}}
}

func (r *escapeRule) Evaluate(ev *Event, st *State) []Detection {
	switch ev.Kind {
	case KindProcess:
		base := path.Base(ev.Process.Exe)
		if _, ok := escapeBinaries[base]; ok {
			meta := map[string]string{"tool": base, "exe": ev.Process.Exe}
			return []Detection{r.fire(ev, "container-escape tool executed: "+base+" (pid "+itoa(ev.Process.PID)+")", meta)}
		}
	case KindSyscall:
		if ev.Syscall == nil {
			return nil
		}
		if _, ok := escapeSyscalls[ev.Syscall.Name]; ok {
			// A mount of the host root or a namespace switch is the tell.
			meta := map[string]string{"syscall": ev.Syscall.Name}
			for k, v := range ev.Syscall.Args {
				meta[k] = v
			}
			return []Detection{r.fire(ev, "namespace/mount escape syscall: "+ev.Syscall.Name+describeSyscallArgs(ev.Syscall), meta)}
		}
	case KindFile:
		if ev.File == nil {
			return nil
		}
		if pre, ok := matchesAnyPrefix(ev.File.Path, hostEscapePaths); ok {
			meta := map[string]string{"path": ev.File.Path, "matched": pre, "op": ev.File.Op}
			return []Detection{r.fire(ev, "access to host-escape path "+ev.File.Path+" ("+ev.File.Op+")", meta)}
		}
	}
	return nil
}

// describeSyscallArgs renders salient syscall args for the message (source/target
// for mount, etc.), deterministically ordered.
func describeSyscallArgs(s *SyscallEvent) string {
	if s == nil || len(s.Args) == 0 {
		return ""
	}
	var parts []string
	for _, k := range []string{"source", "target", "fstype", "flags"} {
		if v, ok := s.Args[k]; ok {
			parts = append(parts, k+"="+v)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// --- DS-RAT-RT-009 privilege escalation --------------------------------------

type privEscRule struct{ ruleBase }

func newPrivEscRule() Rule {
	return &privEscRule{ruleBase{
		id: "DS-RAT-RT-009",
		info: RuleInfo{
			Title:       "Privilege escalation attempt",
			Severity:    engine.SeverityHigh,
			Technique:   techElevControl,
			Default:     true,
			Description: "A process attempted to elevate privileges: executing sudo/su, adding a setuid bit, or wielding a dangerous capability (CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SYS_MODULE) inside a container.",
			Remediation: "Run as non-root with `allowPrivilegeEscalation: false` and `no_new_privs`. Drop all capabilities and add back only what is required. Remove setuid binaries from images.",
		},
	}}
}

func (r *privEscRule) Evaluate(ev *Event, st *State) []Detection {
	switch ev.Kind {
	case KindProcess:
		base := path.Base(ev.Process.Exe)
		if base == "sudo" || base == "su" || base == "doas" || base == "pkexec" {
			meta := map[string]string{"tool": base, "uid": itoa(ev.Process.UID)}
			return []Detection{r.fire(ev, "privilege-escalation tool executed: "+base+" (pid "+itoa(ev.Process.PID)+")", meta)}
		}
		// A container process wielding a dangerous effective capability.
		if cap, ok := dangerousCap(ev.Process.Caps); ok {
			meta := map[string]string{"capability": cap}
			return []Detection{r.fire(ev, "process holds dangerous capability "+cap+" (pid "+itoa(ev.Process.PID)+")", meta)}
		}
	case KindFile:
		if ev.File == nil {
			return nil
		}
		// chmod adding a setuid/setgid bit is a persistence/escalation primitive.
		if ev.File.Op == "chmod" && (ev.File.Mode&0o4000 != 0 || ev.File.Mode&0o2000 != 0) {
			meta := map[string]string{"path": ev.File.Path, "mode": "0" + octal(ev.File.Mode)}
			return []Detection{r.fire(ev, "setuid/setgid bit set on "+ev.File.Path, meta)}
		}
	}
	return nil
}

// dangerousCap returns the first high-risk capability held, if any.
func dangerousCap(caps []string) (string, bool) {
	dangerous := map[string]struct{}{
		"CAP_SYS_ADMIN": {}, "CAP_SYS_MODULE": {}, "CAP_SYS_PTRACE": {},
		"CAP_SYS_BOOT": {}, "CAP_DAC_READ_SEARCH": {}, "CAP_BPF": {},
	}
	for _, c := range caps {
		if _, ok := dangerous[strings.ToUpper(c)]; ok {
			return strings.ToUpper(c), true
		}
	}
	return "", false
}

// octal renders a file mode's permission bits in octal for messages.
func octal(mode uint32) string {
	const digits = "01234567"
	// Only the low 12 bits (setuid/setgid/sticky + rwx) are interesting.
	m := mode & 0o7777
	buf := []byte{digits[(m>>9)&7], digits[(m>>6)&7], digits[(m>>3)&7], digits[m&7]}
	return string(buf)
}
