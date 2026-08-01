package runtime

import (
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// This file holds the fileless-execution rule: processes running from
// anonymous/in-memory backing (no path on disk an investigator can pull), the
// hallmark of reflective loading used to dodge file-based AV/EDR and forensic
// recovery.

// --- DS-RAT-RT-012 fileless execution -----------------------------------------

type filelessRule struct{ ruleBase }

func newFilelessRule() Rule {
	return &filelessRule{ruleBase{
		id: "DS-RAT-RT-012",
		info: RuleInfo{
			Title:       "Fileless execution",
			Severity:    engine.SeverityCritical,
			Technique:   techReflectiveLoad,
			Default:     true,
			Description: "A process executed from anonymous or in-memory backing (tmpfs shared memory, an anonymous memfd, or a deleted file still mapped for exec) rather than a real on-disk path, or a process called memfd_create to stage such a payload. This is the signature of reflective code loading used to evade file-based detection and leave nothing recoverable on disk.",
			Remediation: "Isolate the container and capture memory/forensics before it can be torn down — the payload has no on-disk artifact once the process exits. Investigate how the anonymous executable was staged (e.g. via a network fetch or an interpreter's exec/memfd primitive) and block memfd-backed execution where feasible (seccomp on memfd_create, exec restrictions).",
		},
	}}
}

func (r *filelessRule) Evaluate(ev *Event, st *State) []Detection {
	if ev.Kind == KindProcess && isAnonymousExec(ev.Process.Exe) {
		meta := map[string]string{"exe": ev.Process.Exe, "vector": "anonymous-exec"}
		return []Detection{r.fire(ev, "fileless execution: "+ev.Process.Exe+" (pid "+itoa(ev.Process.PID)+") has no on-disk backing", meta)}
	}
	if ev.Kind == KindSyscall && ev.Syscall != nil && ev.Syscall.Name == "memfd_create" {
		meta := map[string]string{"syscall": "memfd_create", "vector": "memfd"}
		return []Detection{r.fire(ev, "memfd_create called (pid "+itoa(ev.Process.PID)+") — anonymous in-memory file staged", meta)}
	}
	return nil
}

// isAnonymousExec reports whether an executable path indicates anonymous or
// in-memory backing rather than a real file on disk.
func isAnonymousExec(exe string) bool {
	if exe == "" {
		return false
	}
	return strings.HasPrefix(exe, "/dev/shm/") ||
		strings.Contains(exe, "memfd:") ||
		strings.HasSuffix(exe, "(deleted)") ||
		strings.Contains(exe, "(deleted)")
}
