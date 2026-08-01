package runtime

import (
	"path/filepath"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// This file holds the container-runtime-binary-tamper rule. It complements
// DS-RAT-RT-003 (container escape) with the specific host-runtime-binary
// signal the 2024-2025 runc CVEs abuse (e.g. CVE-2024-21626): overwriting the
// runtime binary via /proc/self/exe or /proc/self/fd/N, or the runtime binary
// itself running from a deleted/anonymous/tmp location instead of its normal
// install path.

// runtimeTamperPaths are file-write primitives that let a process rewrite the
// host container-runtime binary out from under itself.
var runtimeTamperPaths = []string{"/proc/self/exe", "/proc/self/fd/"}

// runtimeBinaries are container-runtime executables that should only ever run
// from a normal install location (/usr/bin, /usr/sbin, ...).
var runtimeBinaries = map[string]bool{
	"runc":            true,
	"containerd-shim": true,
	"crun":            true,
	"docker-runc":     true,
}

// --- DS-RAT-RT-013 container runtime tamper ----------------------------------

type runtimeBinaryRule struct{ ruleBase }

func newRuntimeBinaryRule() Rule {
	return &runtimeBinaryRule{ruleBase{
		id: "DS-RAT-RT-013",
		info: RuleInfo{
			Title:       "Container runtime tamper",
			Severity:    engine.SeverityCritical,
			Technique:   techEscapeToHost,
			Default:     true,
			Description: "A process wrote to a host-runtime-escape primitive (/proc/self/exe, /proc/self/fd/N, or a runtime binary such as runc/containerd-shim/crun), or a runtime binary is executing from a deleted/anonymous/tmp location instead of its normal install path — the signal the 2024-2025 runc CVEs (e.g. CVE-2024-21626) abuse to overwrite the host runtime.",
			Remediation: "Assume host-runtime compromise. Cordon and investigate the node; verify the integrity of the installed runc/containerd-shim/crun binaries against a known-good hash and reinstall from a trusted package. Run containers with a read-only root filesystem and drop CAP_SYS_ADMIN to remove the primitive.",
		},
	}}
}

func (r *runtimeBinaryRule) Evaluate(ev *Event, st *State) []Detection {
	switch ev.Kind {
	case KindFile:
		if ev.File == nil || !fileIsWrite(ev.File) {
			return nil
		}
		path := ev.File.Path
		if _, ok := matchesAnyPrefix(path, runtimeTamperPaths); ok || containsRuntimeBinaryName(path) {
			meta := map[string]string{"path": path, "op": ev.File.Op, "vector": "runtime-tamper"}
			return []Detection{r.fire(ev, "write to container-runtime primitive "+path+" ("+ev.File.Op+")", meta)}
		}
	case KindProcess:
		base := filepath.Base(ev.Process.Exe)
		if runtimeBinaries[base] && isSuspectRuntimeLocation(ev.Process.Exe) {
			meta := map[string]string{"exe": ev.Process.Exe, "vector": "runtime-exec"}
			return []Detection{r.fire(ev, "runtime binary "+base+" executing from suspect location "+ev.Process.Exe, meta)}
		}
	}
	return nil
}

// containsRuntimeBinaryName reports whether a write targets a file that IS a
// known container-runtime binary. It matches on the path's base name at word
// boundaries (hyphen/dot/underscore-delimited tokens), NOT a raw substring over
// the whole path — otherwise unrelated files like /var/lib/app/truncate.dat
// ("runc" ⊂ "truncate") would raise a Critical runtime-tamper alert.
func containsRuntimeBinaryName(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if runtimeBinaries[base] || strings.HasPrefix(base, "containerd-shim") {
		return true
	}
	for _, tok := range strings.FieldsFunc(base, func(r rune) bool { return r == '-' || r == '.' || r == '_' }) {
		if tok == "runc" || tok == "crun" {
			return true
		}
	}
	return false
}

// isSuspectRuntimeLocation reports whether a runtime binary's exe path is NOT
// a normal install location — a deleted/anonymous inode or a world-writable
// scratch dir, the tell for a runtime binary overwritten via /proc/self/exe.
func isSuspectRuntimeLocation(exe string) bool {
	return strings.Contains(exe, "(deleted)") ||
		strings.Contains(exe, "/proc/") ||
		strings.Contains(exe, "/tmp/") ||
		strings.Contains(exe, "/dev/shm/")
}
