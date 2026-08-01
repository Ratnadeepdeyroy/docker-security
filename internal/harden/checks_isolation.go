package harden

import (
	"path"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Isolation & resource-limit checks ---------------------------------------
//
// These controls keep the container's view of the host narrow: confinement
// profiles applied, no host namespaces shared, no dangerous host paths (above
// all the docker socket) bind-mounted in, an immutable rootfs, and cgroup limits
// that stop one container starving the node. They map to CIS Docker Benchmark §5
// and MITRE ATT&CK T1610/T1611.

func checkReadOnlyRootFS(w *Workload) []Result {
	c := Control{
		ID:       "DS-RAT-BOX-006",
		Title:    "Root filesystem is writable",
		Severity: engine.SeverityMedium,
		Remediation: "Set the root filesystem read-only (--read-only / readOnlyRootFilesystem: true) " +
			"and mount tmpfs/emptyDir for the few writable paths the workload needs.",
		References: []string{"CIS Docker Benchmark 5.12", "MITRE ATT&CK T1610", "NIST SP 800-190 4.5.3"},
	}
	if w.ReadOnlyRootFS {
		return pass(c, w.Name)
	}
	return warn(c, w.Name, "the container root filesystem is writable, so an attacker can drop tools or tamper with binaries in place")
}

func checkSeccomp(w *Workload) []Result {
	c := Control{
		ID:       "DS-RAT-BOX-007",
		Title:    "Seccomp profile is not applied",
		Severity: engine.SeverityHigh,
		Remediation: "Apply a seccomp profile (RuntimeDefault at minimum, or a generated " +
			"least-privilege profile — see `dsecrat harden gen-profile`). Never run seccomp=unconfined.",
		References: []string{"CIS Docker Benchmark 5.21", "MITRE ATT&CK T1611", "NIST SP 800-190 4.5.3"},
	}
	switch w.Seccomp {
	case SeccompUnconfined:
		return fail(c, w.Name, "seccomp is explicitly unconfined: every syscall, including the dangerous ones, is reachable")
	case SeccompUnset:
		return warn(c, w.Name, "no seccomp profile is asserted by the spec; apply RuntimeDefault or a generated profile")
	default:
		return pass(c, w.Name)
	}
}

func checkAppArmor(w *Workload) []Result {
	c := Control{
		ID:       "DS-RAT-BOX-008",
		Title:    "AppArmor profile is not applied",
		Severity: engine.SeverityMedium,
		Remediation: "Apply an AppArmor profile (runtime/default, or a generated least-privilege " +
			"profile). Do not run apparmor=unconfined on hosts where AppArmor is available.",
		References: []string{"CIS Docker Benchmark 5.1", "MITRE ATT&CK T1611", "NIST SP 800-190 4.5.3"},
	}
	switch strings.ToLower(w.AppArmor) {
	case "unconfined":
		return fail(c, w.Name, "AppArmor is explicitly unconfined")
	case "":
		return warn(c, w.Name, "no AppArmor profile is asserted by the spec")
	default:
		return pass(c, w.Name)
	}
}

func checkHostNamespaces(w *Workload) []Result {
	c := Control{
		ID:       "DS-RAT-BOX-009",
		Title:    "Container shares a host namespace",
		Severity: engine.SeverityHigh,
		Remediation: "Do not share host namespaces: drop hostPID/hostIPC/hostNetwork (and give the " +
			"container its own OCI pid/ipc/network namespaces).",
		References: []string{"CIS Docker Benchmark 5.9", "MITRE ATT&CK T1611", "NIST SP 800-190 4.5.1"},
	}
	shared := []struct {
		on   bool
		kind string
		why  string
	}{
		{w.HostPID, "hostPID", "sees and can signal every process on the host"},
		{w.HostIPC, "hostIPC", "can access host shared-memory segments and IPC"},
		{w.HostNetwork, "hostNetwork", "shares the host network stack, bypassing network policy and reaching loopback services"},
	}
	var out []Result
	for _, s := range shared {
		if s.on {
			out = append(out, fail(c, w.Name+":"+s.kind, "shares "+s.kind+": the container "+s.why)...)
		}
	}
	if out == nil {
		return pass(c, w.Name)
	}
	return out
}

func checkDockerSock(w *Workload) []Result {
	c := Control{
		ID:       "DS-RAT-BOX-010",
		Title:    "Docker/container runtime socket is mounted into the container",
		Severity: engine.SeverityCritical,
		Remediation: "Never mount docker.sock (or containerd.sock) into a workload. If the workload " +
			"must orchestrate containers, use a scoped API with authz, not the raw socket.",
		References: []string{"CIS Docker Benchmark 5.31", "MITRE ATT&CK T1610", "NIST SP 800-190 4.5.2"},
	}
	var out []Result
	for _, m := range w.Mounts {
		if isRuntimeSocket(m.Source) || isRuntimeSocket(m.Destination) {
			src := m.Source
			if src == "" {
				src = m.Destination
			}
			out = append(out, fail(c, w.Name+":"+src, "mounts the runtime socket "+src+": full control of the host's containers (trivial host takeover)")...)
		}
	}
	if out == nil {
		return pass(c, w.Name)
	}
	return out
}

func checkSensitiveMounts(w *Workload) []Result {
	var out []Result
	for _, m := range w.Mounts {
		if m.Source == "" || isRuntimeSocket(m.Source) {
			continue // tmpfs/volume, or the socket handled by DS-RAT-BOX-010
		}
		sev, base, ok := sensitiveMountSeverity(m.Source)
		if !ok {
			continue
		}
		c := Control{
			ID:       "DS-RAT-BOX-011",
			Title:    "Sensitive host path is bind-mounted into the container",
			Severity: sev,
			Remediation: "Remove the bind mount of " + base + " or scope it to a specific, non-sensitive " +
				"subpath mounted read-only.",
			References: []string{"CIS Docker Benchmark 5.5", "MITRE ATT&CK T1610", "NIST SP 800-190 4.5.2"},
		}
		mode := "read-write"
		if m.ReadOnly {
			mode = "read-only"
		}
		out = append(out, fail(c, w.Name+":"+m.Source, "bind-mounts host path "+m.Source+" ("+mode+"): exposes sensitive host state to the container")...)
	}
	return out
}

func checkMemoryLimit(w *Workload) []Result {
	c := Control{
		ID:       "DS-RAT-BOX-012",
		Title:    "No memory limit is set",
		Severity: engine.SeverityMedium,
		Remediation: "Set a memory limit (--memory / resources.limits.memory) so one container cannot " +
			"exhaust host memory and OOM its neighbours.",
		References: []string{"CIS Docker Benchmark 5.10", "MITRE ATT&CK T1499", "NIST SP 800-190 4.5.1"},
	}
	if w.MemoryLimitBytes > 0 {
		return pass(c, w.Name)
	}
	return warn(c, w.Name, "no memory limit: a leak or fork/alloc bomb can starve the whole node")
}

func checkPidsLimit(w *Workload) []Result {
	c := Control{
		ID:       "DS-RAT-BOX-013",
		Title:    "No PID limit is set",
		Severity: engine.SeverityMedium,
		Remediation: "Set a pids limit (--pids-limit / an OCI pids cgroup) to bound fork bombs. " +
			"In Kubernetes this is enforced node-wide via kubelet podPidsLimit.",
		References: []string{"CIS Docker Benchmark 5.28", "MITRE ATT&CK T1499", "NIST SP 800-190 4.5.1"},
	}
	if w.PidsLimit > 0 {
		return pass(c, w.Name)
	}
	// Kubernetes has no per-container pids field, so this is a spec gap rather
	// than a definite misconfiguration there.
	if w.Source == "kubernetes" {
		return info(c, w.Name, "no per-container pids limit in the pod spec; confirm kubelet podPidsLimit is set node-wide")
	}
	return warn(c, w.Name, "no pids limit: a fork bomb inside the container can exhaust host PIDs")
}

func checkMaskedPaths(w *Workload) []Result {
	c := Control{
		ID:       "DS-RAT-BOX-016",
		Title:    "Dangerous procfs/sysfs paths are not masked",
		Severity: engine.SeverityMedium,
		Remediation: "Keep the runtime's default maskedPaths/readonlyPaths (e.g. /proc/kcore, " +
			"/proc/sysrq-trigger, /sys/firmware) — do not clear them.",
		References: []string{"CIS Docker Benchmark 5.4", "MITRE ATT&CK T1611", "NIST SP 800-190 4.5.3"},
	}
	// Only the OCI spec exposes these explicitly; a privileged spec clears them,
	// which DS-RAT-BOX-001 already flags.
	if w.Source != "oci" || w.Privileged {
		return []Result{{Control: c, Status: StatusNA, Resource: w.Name, Evidence: "not applicable"}}
	}
	if len(w.MaskedPaths) == 0 {
		return warn(c, w.Name, "no maskedPaths set: /proc/kcore, /proc/sysrq-trigger and similar host-tampering paths are exposed")
	}
	return pass(c, w.Name)
}

// --- helpers -----------------------------------------------------------------

// isRuntimeSocket reports whether a path is a container runtime control socket.
func isRuntimeSocket(p string) bool {
	base := path.Base(strings.TrimSpace(p))
	switch base {
	case "docker.sock", "containerd.sock", "crio.sock", "podman.sock":
		return true
	}
	return false
}

// sensitiveHostPaths grades host paths whose exposure hands over meaningful host
// state or control. Longest, most-specific prefixes are graded highest.
var sensitiveHostPaths = []struct {
	prefix string
	sev    engine.Severity
}{
	{"/var/lib/docker", engine.SeverityCritical},
	{"/var/lib/kubelet", engine.SeverityHigh},
	{"/var/lib/containerd", engine.SeverityHigh},
	{"/etc", engine.SeverityHigh},
	{"/root", engine.SeverityHigh},
	{"/boot", engine.SeverityHigh},
	{"/proc", engine.SeverityHigh},
	{"/sys", engine.SeverityHigh},
	{"/dev", engine.SeverityHigh},
	{"/var/run", engine.SeverityHigh},
	{"/run", engine.SeverityHigh},
	{"/home", engine.SeverityMedium},
	{"/usr", engine.SeverityMedium},
	{"/bin", engine.SeverityMedium},
	{"/sbin", engine.SeverityMedium},
	{"/lib", engine.SeverityMedium},
}

// sensitiveMountSeverity classifies a host source path. The whole-root mount is
// the worst case; otherwise the most specific matching prefix wins.
func sensitiveMountSeverity(source string) (engine.Severity, string, bool) {
	clean := path.Clean(strings.TrimSpace(source))
	if clean == "/" {
		return engine.SeverityCritical, "/", true
	}
	best := ""
	var bestSev engine.Severity
	for _, sp := range sensitiveHostPaths {
		if clean == sp.prefix || strings.HasPrefix(clean, sp.prefix+"/") {
			if len(sp.prefix) > len(best) {
				best = sp.prefix
				bestSev = sp.sev
			}
		}
	}
	if best == "" {
		return 0, "", false
	}
	return bestSev, best, true
}
