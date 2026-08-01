package runtime

import (
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// This file covers kernel-level abuse — rootkit installation, eBPF abuse, and
// loadable-kernel-module loading. It is a deliberately named market gap: many
// runtime sensors watch userspace behavior but under-cover the kernel surface an
// attacker uses to hide (a rootkit that unhooks the very sensor watching it).
// From inside a container, any of these is a severe, high-confidence signal.

// --- DS-RAT-RT-008 kernel rootkit / eBPF abuse / LKM load --------------------

type kernelAbuseRule struct{ ruleBase }

func newKernelAbuseRule() Rule {
	return &kernelAbuseRule{ruleBase{
		id: "DS-RAT-RT-008",
		info: RuleInfo{
			Title:       "Kernel abuse: rootkit / eBPF / module load",
			Severity:    engine.SeverityCritical,
			Technique:   techKernelModule,
			Default:     true,
			Description: "A container attempted to manipulate the kernel: loading/unloading a kernel module (init_module/finit_module/delete_module), loading an eBPF program (bpf syscall) from an untrusted workload, or accessing rootkit-adjacent interfaces (/dev/kmsg raw write, kallsyms, /proc/kallsyms, kernel module files). Kernel tampering is how sophisticated attackers hide from the sensor itself.",
			Remediation: "Drop CAP_SYS_MODULE and CAP_BPF from all workloads; set kernel.modules_disabled=1 on hardened nodes. No application container should load modules or eBPF — treat this as a critical incident and forensically image the node.",
		},
	}}
}

func (r *kernelAbuseRule) Evaluate(ev *Event, st *State) []Detection {
	switch ev.Kind {
	case KindSyscall:
		if ev.Syscall == nil {
			return nil
		}
		name := ev.Syscall.Name
		// Loadable kernel module operations.
		if _, ok := kernelModuleSyscalls[name]; ok {
			meta := map[string]string{"syscall": name, "vector": "lkm"}
			for k, v := range ev.Syscall.Args {
				meta[k] = v
			}
			return []Detection{r.fire(ev, "kernel module operation from container: "+name+describeSyscallArgs(ev.Syscall), meta)}
		}
		// eBPF program load / map manipulation from a container.
		if name == "bpf" {
			cmd := ev.Syscall.Args["cmd"]
			meta := map[string]string{"syscall": "bpf", "cmd": cmd, "vector": "ebpf"}
			return []Detection{r.fire(ev, "eBPF syscall from container (cmd="+orNA(cmd)+") — possible eBPF-based rootkit or sensor evasion", meta)}
		}
	case KindFile:
		if ev.File == nil {
			return nil
		}
		if reason, ok := kernelSensitiveFile(ev.File.Path); ok {
			meta := map[string]string{"path": ev.File.Path, "reason": reason, "vector": "kernel-iface"}
			d := r.fire(ev, "access to kernel interface "+ev.File.Path+" ("+reason+")", meta)
			// Reading kernel symbols / debug interfaces or a module file is
			// rootkit-adjacent (hiding/hooking) rather than a module load per se,
			// so map the file vector to Rootkit (T1014) specifically.
			d.Technique = techRootkit
			d.References = []string{techRootkit.URL}
			return []Detection{d}
		}
	}
	return nil
}

// kernelSensitiveFile flags file paths used for rootkit installation or kernel
// interrogation.
func kernelSensitiveFile(p string) (string, bool) {
	switch {
	case strings.HasPrefix(p, "/lib/modules/"), strings.HasSuffix(p, ".ko"):
		return "kernel module file", true
	case p == "/proc/kallsyms", p == "/sys/kernel/debug/kprobes":
		return "kernel symbol/probe interface", true
	case strings.HasPrefix(p, "/sys/kernel/debug/"):
		return "kernel debug interface", true
	case p == "/dev/kmsg":
		return "kernel message device", true
	}
	return "", false
}

func orNA(s string) string {
	if s == "" {
		return "n/a"
	}
	return s
}
