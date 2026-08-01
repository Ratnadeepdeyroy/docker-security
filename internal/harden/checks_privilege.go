package harden

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Privilege & capability checks -------------------------------------------
//
// These are the controls that decide how much a compromised process inside the
// container can do to the host: whether it is privileged, runs as root, keeps
// dangerous capabilities, can gain new privileges, and whether a setuid binary
// in the image can still escalate. They map to CIS Docker Benchmark §5 and to
// MITRE ATT&CK T1611 (Escape to Host).

// dockerDefaultCaps is the capability set a container keeps by default when it
// does not drop ALL. Reproduced here (bare, upper-case) so heldCaps can reason
// about "what does this workload actually hold" without a live runtime.
var dockerDefaultCaps = []string{
	"AUDIT_WRITE", "CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL",
	"MKNOD", "NET_BIND_SERVICE", "NET_RAW", "SETFCAP", "SETGID", "SETPCAP",
	"SETUID", "SYS_CHROOT",
}

// dangerousCaps grades the capabilities that materially widen the escape surface.
// Severities reflect how directly the capability leads to host compromise:
// SYS_ADMIN/SYS_MODULE/SYS_RAWIO are effectively root-on-host.
var dangerousCaps = map[string]engine.Severity{
	"SYS_ADMIN":       engine.SeverityCritical,
	"SYS_MODULE":      engine.SeverityCritical,
	"SYS_RAWIO":       engine.SeverityCritical,
	"BPF":             engine.SeverityHigh,
	"DAC_READ_SEARCH": engine.SeverityHigh,
	"DAC_OVERRIDE":    engine.SeverityHigh,
	"SYS_PTRACE":      engine.SeverityHigh,
	"NET_ADMIN":       engine.SeverityHigh,
	"SYS_BOOT":        engine.SeverityHigh,
	"PERFMON":         engine.SeverityHigh,
	"MAC_ADMIN":       engine.SeverityHigh,
	"MAC_OVERRIDE":    engine.SeverityHigh,
	"SYSLOG":          engine.SeverityMedium,
	"SYS_TIME":        engine.SeverityMedium,
	"SYS_RESOURCE":    engine.SeverityMedium,
	"NET_RAW":         engine.SeverityMedium,
	"MKNOD":           engine.SeverityMedium,
	"IPC_OWNER":       engine.SeverityMedium,
	"AUDIT_CONTROL":   engine.SeverityMedium,
	"LINUX_IMMUTABLE": engine.SeverityMedium,
}

// heldCaps computes the capabilities a workload effectively holds. A privileged
// container holds everything; otherwise the held set is the explicitly-added
// caps when ALL was dropped, or the Docker default set plus adds minus drops.
func (w *Workload) heldCaps() []string {
	if w.Privileged {
		// Privileged grants the full bounding set; the dangerous ones are what
		// matters downstream, so report those.
		out := make([]string, 0, len(dangerousCaps))
		for c := range dangerousCaps {
			out = append(out, c)
		}
		sort.Strings(out)
		return out
	}
	if containsFold(w.CapDrop, "ALL") {
		return normalizeCaps(w.CapAdd)
	}
	base := map[string]bool{}
	for _, c := range dockerDefaultCaps {
		base[c] = true
	}
	for _, c := range normalizeCaps(w.CapAdd) {
		base[c] = true
	}
	for _, c := range normalizeCaps(w.CapDrop) {
		delete(base, c)
	}
	out := make([]string, 0, len(base))
	for c := range base {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

func checkPrivileged(w *Workload) []Result {
	c := Control{
		ID:       "DS-RAT-BOX-001",
		Title:    "Container runs in privileged mode",
		Severity: engine.SeverityCritical,
		Remediation: "Remove --privileged / securityContext.privileged. Grant only the " +
			"specific capabilities and device access the workload needs.",
		References: []string{"CIS Docker Benchmark 5.4", "MITRE ATT&CK T1611", "NIST SP 800-190 4.5.2"},
	}
	if w.Privileged {
		return fail(c, w.Name, "workload is privileged: it holds all capabilities and unrestricted device access, which is equivalent to root on the host")
	}
	return pass(c, w.Name)
}

func checkRunAsRoot(w *Workload) []Result {
	c := Control{
		ID:       "DS-RAT-BOX-002",
		Title:    "Container runs as root (UID 0)",
		Severity: engine.SeverityHigh,
		Remediation: "Set a non-zero runAsUser (or a USER in the image) and runAsNonRoot: true " +
			"so the kernel refuses to start the container as root.",
		References: []string{"CIS Docker Benchmark 4.1", "MITRE ATT&CK T1611", "NIST SP 800-190 4.2.2"},
	}
	// runAsNonRoot: true is an explicit guarantee, regardless of the numeric UID.
	if w.RunAsNonRoot != nil && *w.RunAsNonRoot {
		return pass(c, w.Name)
	}
	switch {
	case w.RunAsUser != nil && *w.RunAsUser == 0:
		return fail(c, w.Name, "runs as UID 0 (root)")
	case w.RunAsUser != nil: // explicit non-zero uid
		return pass(c, w.Name)
	default:
		// No user asserted and no runAsNonRoot: the default is root for most images.
		return warn(c, w.Name, "no non-root user is asserted; the image likely defaults to root — set runAsNonRoot: true")
	}
}

func checkCapDropAll(w *Workload) []Result {
	c := Control{
		ID:       "DS-RAT-BOX-003",
		Title:    "Capabilities are not reduced to a minimal set",
		Severity: engine.SeverityHigh,
		Remediation: "Drop ALL capabilities and add back only those the workload needs " +
			"(capabilities.drop: [ALL]).",
		References: []string{"CIS Docker Benchmark 5.3", "MITRE ATT&CK T1611", "NIST SP 800-190 4.5.3"},
	}
	if w.Privileged {
		// Privileged makes cap-dropping moot; DS-RAT-BOX-001 already fails.
		return []Result{{Control: c, Status: StatusNA, Resource: w.Name, Evidence: "not applicable: workload is privileged"}}
	}
	if containsFold(w.CapDrop, "ALL") {
		return pass(c, w.Name)
	}
	return fail(c, w.Name, "does not drop ALL capabilities; it keeps the default set "+strings.Join(dockerDefaultCaps, ", "))
}

func checkDangerousCaps(w *Workload) []Result {
	// On an OCI spec, --privileged auto-expands to the full bounding set, so the
	// individual dangerous caps are not a distinct operator choice — DS-RAT-BOX-001
	// covers it. On Kubernetes, capabilities.add sits *alongside* privileged as a
	// separately-authored line worth flagging on its own, so we still report it.
	if w.Privileged && w.Source == "oci" {
		return nil
	}
	var out []Result
	// Only inspect what was explicitly added: for OCI that is the whole bounding
	// set, for Kubernetes it is capabilities.add — either way, the caps beyond the
	// default that the operator deliberately granted.
	for _, cap := range normalizeCaps(w.CapAdd) {
		sev, bad := dangerousCaps[cap]
		if !bad {
			continue
		}
		c := Control{
			ID:       "DS-RAT-BOX-004",
			Title:    "Escape-prone Linux capability granted",
			Severity: sev,
			Remediation: fmt.Sprintf("Remove CAP_%s unless strictly required; prefer a narrower "+
				"capability or a device/host interface with tighter scope.", cap),
			References: []string{"CIS Docker Benchmark 5.3", "MITRE ATT&CK T1611", "NIST SP 800-190 4.5.3"},
		}
		out = append(out, fail(c, w.Name+":CAP_"+cap, "grants CAP_"+cap+", which can be leveraged to escape the container or tamper with the host")...)
	}
	return out
}

func checkNoNewPrivileges(w *Workload) []Result {
	c := Control{
		ID:       "DS-RAT-BOX-005",
		Title:    "no-new-privileges is not set",
		Severity: engine.SeverityMedium,
		Remediation: "Set no-new-privileges (OCI process.noNewPrivileges: true, or Kubernetes " +
			"allowPrivilegeEscalation: false) to stop a process gaining privileges via setuid/file caps.",
		References: []string{"CIS Docker Benchmark 5.25", "MITRE ATT&CK T1611", "NIST SP 800-190 4.5.3"},
	}
	if w.NoNewPrivileges {
		return pass(c, w.Name)
	}
	return fail(c, w.Name, "no-new-privileges is off: a setuid-root or file-capability binary can still escalate")
}

func checkSetuidNeutralized(w *Workload) []Result {
	c := Control{
		ID:       "DS-RAT-BOX-015",
		Title:    "setuid/setgid escalation is not neutralized",
		Severity: engine.SeverityMedium,
		Remediation: "Neutralize setuid: set no-new-privileges AND drop CAP_SETUID/CAP_SETGID; " +
			"mount writable volumes with nosuid; prefer images built without setuid binaries.",
		References: []string{"CIS Docker Benchmark 5.25", "MITRE ATT&CK T1611", "NIST SP 800-190 4.4.2"},
	}
	held := w.heldCaps()
	hasSetuid := containsFold(held, "SETUID") || containsFold(held, "SETGID")
	// Fully neutralized when privileges cannot be gained AND the caps that make
	// setuid meaningful are gone. This is the named market gap: even a hardened
	// pod that "drops ALL" but leaves no-new-privileges unset stays exposed.
	if w.NoNewPrivileges && !hasSetuid {
		return pass(c, w.Name)
	}
	var why []string
	if !w.NoNewPrivileges {
		why = append(why, "no-new-privileges is off")
	}
	if hasSetuid {
		why = append(why, "the workload retains CAP_SETUID/CAP_SETGID")
	}
	return warn(c, w.Name, "a setuid-root binary in the image could escalate privileges: "+strings.Join(why, " and "))
}

func checkUserNamespace(w *Workload) []Result {
	c := Control{
		ID:       "DS-RAT-BOX-014",
		Title:    "User namespace remapping is not in effect",
		Severity: engine.SeverityMedium,
		Remediation: "Enable user-namespace remapping (userns-remap / Kubernetes hostUsers: false, " +
			"or an OCI user namespace with uid/gid mappings) so container UID 0 is not host UID 0.",
		References: []string{"CIS Docker Benchmark 5.30", "MITRE ATT&CK T1611", "NIST SP 800-190 4.5.4"},
	}
	if !w.HostUsers {
		return pass(c, w.Name)
	}
	return warn(c, w.Name, "shares the host user namespace: an in-container root user maps to host root, removing a key escape barrier")
}
