package dockerbench

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/compliance"
)

// --- Section 5: Container Runtime ------------------------------------------
//
// Runtime controls apply per container. Each check runs a predicate over every
// container in the evidence; the control FAILs if any container violates it
// (listing offenders deterministically), PASSes if none do, and is INFO when no
// containers were collected.

func runtimeControls() []compliance.Control {
	return []compliance.Control{
		rc("5.1", "Ensure AppArmor profile is enabled", compliance.Level1,
			"Running a container with apparmor=unconfined removes mandatory-access-control confinement.",
			"Do not set --security-opt apparmor=unconfined; keep the docker-default profile or a custom one.",
			nist190("4.4.1"), nist53("AC-3"), stig("SRG-APP-000233")),
		rc("5.3", "Ensure Linux kernel capabilities are restricted", compliance.Level1,
			"Adding powerful capabilities (or ALL) re-arms attacks that the default capability set is meant to prevent.",
			"Drop all capabilities and add back only those required (--cap-drop ALL --cap-add ...).",
			nist190("4.4.2"), nist53("AC-6"), stig("SRG-APP-000243")),
		rc("5.4", "Ensure privileged containers are not used", compliance.Level1,
			"A privileged container disables namespace, capability, and seccomp isolation — effectively host root.",
			"Remove --privileged; grant only the specific capabilities/devices needed.",
			nist190("4.4.2"), nist53("AC-6"), stig("SRG-APP-000342"), pci("2.2.1")),
		rc("5.5", "Ensure sensitive host system directories are not mounted", compliance.Level1,
			"Mounting host paths such as / or /etc into a container exposes the host to modification and data theft.",
			"Do not bind-mount sensitive host directories; if unavoidable, mount read-only and narrowly scoped.",
			nist190("4.4.3"), nist53("AC-6"), stig("SRG-APP-000243")),
		rc("5.7", "Ensure privileged ports are not mapped within containers", compliance.Level1,
			"Publishing a container on a host port below 1024 requires elevated privilege and widens the trust surface.",
			"Map containers to non-privileged host ports (>=1024).",
			nist190("4.4.3"), nist53("CM-7"), stig("SRG-APP-000142")),
		rc("5.9", "Ensure the host's network namespace is not shared", compliance.Level1,
			"--network host removes network namespace isolation, letting the container sniff and bind host interfaces.",
			"Do not run with --network host; use bridge or a user-defined network.",
			nist190("4.4.3"), nist53("SC-7"), stig("SRG-APP-000038")),
		rc("5.10", "Ensure memory usage for the container is limited", compliance.Level1,
			"An unbounded container can exhaust host memory and take down co-located workloads (DoS).",
			"Set a memory limit (--memory).",
			nist190("4.4.4"), nist53("SC-6"), stig("SRG-APP-000435")),
		rc("5.12", "Ensure the container's root filesystem is mounted read-only", compliance.Level2,
			"A writable root filesystem lets an attacker persist tools and tamper with the running image.",
			"Run with --read-only and mount tmpfs/volumes only where writes are required.",
			nist190("4.4.4"), nist53("CM-5"), stig("SRG-APP-000133")),
		rc("5.15", "Ensure the host's process namespace is not shared", compliance.Level1,
			"--pid host lets the container see and signal all host processes, breaking isolation.",
			"Do not run with --pid host.",
			nist190("4.4.3"), nist53("SC-39"), stig("SRG-APP-000243")),
		rc("5.16", "Ensure the host's IPC namespace is not shared", compliance.Level1,
			"--ipc host shares System V IPC / shared memory with the host and other containers.",
			"Do not run with --ipc host.",
			nist190("4.4.3"), nist53("SC-39"), stig("SRG-APP-000243")),
		rc("5.20", "Ensure the host's UTS namespace is not shared", compliance.Level1,
			"--uts host lets a container change the host's hostname and domain.",
			"Do not run with --uts host.",
			nist190("4.4.3"), nist53("SC-39"), stig("SRG-APP-000243")),
		rc("5.21", "Ensure the default seccomp profile is not disabled", compliance.Level2,
			"seccomp=unconfined removes syscall filtering, exposing the full kernel attack surface.",
			"Do not set --security-opt seccomp=unconfined; keep the default profile.",
			nist190("4.4.1"), nist53("SC-39"), stig("SRG-APP-000243")),
		rc("5.25", "Ensure containers are restricted from acquiring new privileges", compliance.Level2,
			"Without no-new-privileges, setuid binaries inside the container can escalate privilege.",
			"Run with --security-opt no-new-privileges (or enable it daemon-wide).",
			nist190("4.4.2"), nist53("AC-6"), stig("SRG-APP-000243")),
		rc("5.26", "Ensure container health is checked at runtime", compliance.Level1,
			"Without a healthcheck, orchestrators cannot detect and recycle unhealthy containers.",
			"Define a HEALTHCHECK in the image or --health-cmd at run time.",
			nist190("4.4.4"), nist53("SI-4"), stig("SRG-APP-000516")),
		rc("5.28", "Ensure the PIDs cgroup limit is used", compliance.Level1,
			"An unbounded PID count allows fork-bomb denial of service against the host.",
			"Set --pids-limit to a sensible ceiling.",
			nist190("4.4.4"), nist53("SC-6"), stig("SRG-APP-000435")),
		rc("5.31", "Ensure the Docker socket is not mounted inside any container", compliance.Level1,
			"A container with the Docker socket mounted can control the daemon — a trivial host takeover path.",
			"Never bind-mount /var/run/docker.sock into a container; use a scoped API proxy if needed.",
			nist190("4.4.3"), nist53("AC-6"), stig("SRG-APP-000033"), pci("2.2.1")),
	}
}

// rc constructs a runtime Control (all scored, section fixed) tersely.
func rc(id, title string, level compliance.Level, desc, rem string, refs ...compliance.FrameworkRef) compliance.Control {
	return compliance.Control{
		ID: id, Title: title, Section: secRuntime, Level: level, Scored: true,
		Description: desc, Remediation: rem, Frameworks: refs,
	}
}

// sensitiveHostDirs are host paths that must not be bind-mounted into a
// container. Matching is on the mount source path prefix.
var sensitiveHostDirs = []string{"/", "/boot", "/dev", "/etc", "/lib", "/proc", "/sys", "/usr", "/var"}

// dangerousCaps are capabilities whose presence in --cap-add re-opens attack
// surface the default set intentionally removes.
var dangerousCaps = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "NET_ADMIN": true, "SYS_PTRACE": true,
	"SYS_MODULE": true, "DAC_READ_SEARCH": true, "SYS_RAWIO": true, "NET_RAW": true,
}

// dockerSocketPaths are the socket locations that must never be mounted in.
var dockerSocketPaths = map[string]bool{"/var/run/docker.sock": true, "/run/docker.sock": true}

// perContainer evaluates a predicate against every container. offenders are
// sorted for deterministic output.
func perContainer(e *Evidence, bad func(Container) (bool, string)) compliance.Assessment {
	if len(e.Containers) == 0 {
		return info("no running containers in evidence")
	}
	var offenders []string
	for _, c := range e.Containers {
		if violates, detail := bad(c); violates {
			offenders = append(offenders, fmt.Sprintf("%s (%s)", nameOf(c), detail))
		}
	}
	if len(offenders) == 0 {
		return pass(fmt.Sprintf("all %d container(s) compliant", len(e.Containers)))
	}
	sort.Strings(offenders)
	joined := strings.Join(offenders, "; ")
	return fail(joined, joined)
}

func nameOf(c Container) string { return orDefault(c.Name, "<unnamed>") }

func hasSecOpt(c Container, needle string) bool {
	for _, o := range c.SecurityOpt {
		if strings.Contains(strings.ToLower(strings.ReplaceAll(o, " ", "")), needle) {
			return true
		}
	}
	return false
}

// runtime check functions -----------------------------------------------------

func check51AppArmor(e *Evidence) compliance.Assessment {
	return perContainer(e, func(c Container) (bool, string) {
		if hasSecOpt(c, "apparmor=unconfined") || hasSecOpt(c, "apparmor:unconfined") {
			return true, "apparmor unconfined"
		}
		return false, ""
	})
}

func check53Caps(e *Evidence) compliance.Assessment {
	return perContainer(e, func(c Container) (bool, string) {
		for _, cap := range c.CapAdd {
			if dangerousCaps[strings.ToUpper(strings.TrimPrefix(strings.ToUpper(cap), "CAP_"))] {
				return true, "adds " + cap
			}
		}
		return false, ""
	})
}

func check54Privileged(e *Evidence) compliance.Assessment {
	return perContainer(e, func(c Container) (bool, string) {
		if c.Privileged {
			return true, "privileged"
		}
		return false, ""
	})
}

func check55SensitiveMounts(e *Evidence) compliance.Assessment {
	return perContainer(e, func(c Container) (bool, string) {
		for _, m := range c.Mounts {
			for _, d := range sensitiveHostDirs {
				if m.Source == d {
					return true, "mounts host " + d
				}
			}
		}
		return false, ""
	})
}

func check57PrivilegedPorts(e *Evidence) compliance.Assessment {
	return perContainer(e, func(c Container) (bool, string) {
		for _, p := range c.PortBindings {
			if p.HostPort > 0 && p.HostPort < 1024 {
				return true, fmt.Sprintf("host port %d", p.HostPort)
			}
		}
		return false, ""
	})
}

func check59HostNet(e *Evidence) compliance.Assessment {
	return perContainer(e, func(c Container) (bool, string) {
		if strings.EqualFold(c.NetworkMode, "host") {
			return true, "network=host"
		}
		return false, ""
	})
}

func check510Memory(e *Evidence) compliance.Assessment {
	return perContainer(e, func(c Container) (bool, string) {
		if c.MemoryLimit <= 0 {
			return true, "no memory limit"
		}
		return false, ""
	})
}

func check512ReadonlyRoot(e *Evidence) compliance.Assessment {
	return perContainer(e, func(c Container) (bool, string) {
		if !c.ReadonlyRootfs {
			return true, "writable rootfs"
		}
		return false, ""
	})
}

func check515HostPID(e *Evidence) compliance.Assessment {
	return perContainer(e, func(c Container) (bool, string) {
		if strings.EqualFold(c.PidMode, "host") {
			return true, "pid=host"
		}
		return false, ""
	})
}

func check516HostIPC(e *Evidence) compliance.Assessment {
	return perContainer(e, func(c Container) (bool, string) {
		if strings.EqualFold(c.IpcMode, "host") {
			return true, "ipc=host"
		}
		return false, ""
	})
}

func check520HostUTS(e *Evidence) compliance.Assessment {
	return perContainer(e, func(c Container) (bool, string) {
		if strings.EqualFold(c.UtsMode, "host") {
			return true, "uts=host"
		}
		return false, ""
	})
}

func check521Seccomp(e *Evidence) compliance.Assessment {
	return perContainer(e, func(c Container) (bool, string) {
		if hasSecOpt(c, "seccomp=unconfined") || hasSecOpt(c, "seccomp:unconfined") {
			return true, "seccomp unconfined"
		}
		return false, ""
	})
}

func check525NoNewPrivs(e *Evidence) compliance.Assessment {
	// A daemon-wide no-new-privileges default satisfies this for every container.
	if v, ok := e.daemonBool("no-new-privileges"); ok && v {
		if len(e.Containers) == 0 {
			return pass("no-new-privileges enabled daemon-wide")
		}
	}
	return perContainer(e, func(c Container) (bool, string) {
		if daemonNNP, ok := e.daemonBool("no-new-privileges"); ok && daemonNNP {
			return false, ""
		}
		if !hasSecOpt(c, "no-new-privileges") {
			return true, "may acquire new privileges"
		}
		return false, ""
	})
}

func check526Healthcheck(e *Evidence) compliance.Assessment {
	return perContainer(e, func(c Container) (bool, string) {
		if !c.Healthcheck {
			return true, "no healthcheck"
		}
		return false, ""
	})
}

func check528PidsLimit(e *Evidence) compliance.Assessment {
	return perContainer(e, func(c Container) (bool, string) {
		if c.PidsLimit <= 0 {
			return true, "no pids limit"
		}
		return false, ""
	})
}

func check531DockerSocket(e *Evidence) compliance.Assessment {
	return perContainer(e, func(c Container) (bool, string) {
		for _, m := range c.Mounts {
			if dockerSocketPaths[m.Source] || dockerSocketPaths[m.Destination] {
				return true, "docker.sock mounted"
			}
		}
		return false, ""
	})
}
