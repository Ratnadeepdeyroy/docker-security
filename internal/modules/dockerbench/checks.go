package dockerbench

import "github.com/Ratnadeepdeyroy/docker-security/internal/compliance"

// --- Check dispatch --------------------------------------------------------

// checkFunc assesses one control against collected evidence.
type checkFunc func(*Evidence) compliance.Assessment

// checksFor returns the control-id → check mapping. A control with no entry
// here is a manual/informational control (the runner reports it as INFO).
// Keeping this as one table makes it obvious at a glance which controls are
// automated and which await a check.
func checksFor(e *Evidence) compliance.Assessor {
	table := map[string]checkFunc{
		// Section 2 — daemon
		"2.1": check21ICC, "2.2": check22LogLevel, "2.3": check23Iptables,
		"2.4": check24InsecureRegistries, "2.5": check25StorageDriver, "2.6": check26TLS,
		"2.8": check28UsernsRemap, "2.11": check211AuthzPlugin, "2.12": check212RemoteLogging,
		"2.13": check213LiveRestore, "2.14": check214UserlandProxy, "2.15": check215Seccomp,
		"2.16": check216Experimental, "2.17": check217NoNewPrivs,

		// Section 3 — files
		"3.5": func(e *Evidence) compliance.Assessment { return checkOwnership(e, "/etc/docker", "root", "root") },
		"3.6": func(e *Evidence) compliance.Assessment { return checkPermsAtMost(e, "/etc/docker", 0o755) },
		"3.15": func(e *Evidence) compliance.Assessment {
			return checkOwnership(e, "/var/run/docker.sock", "root", "docker")
		},
		"3.16": func(e *Evidence) compliance.Assessment { return checkPermsAtMost(e, "/var/run/docker.sock", 0o660) },
		"3.17": func(e *Evidence) compliance.Assessment {
			return checkOwnership(e, "/etc/docker/daemon.json", "root", "root")
		},
		"3.18": func(e *Evidence) compliance.Assessment { return checkPermsAtMost(e, "/etc/docker/daemon.json", 0o644) },

		// Section 5 — runtime
		"5.1": check51AppArmor, "5.3": check53Caps, "5.4": check54Privileged, "5.5": check55SensitiveMounts,
		"5.7": check57PrivilegedPorts, "5.9": check59HostNet, "5.10": check510Memory, "5.12": check512ReadonlyRoot,
		"5.15": check515HostPID, "5.16": check516HostIPC, "5.20": check520HostUTS, "5.21": check521Seccomp,
		"5.25": check525NoNewPrivs, "5.26": check526Healthcheck, "5.28": check528PidsLimit, "5.31": check531DockerSocket,
	}

	return func(c compliance.Control) compliance.Assessment {
		if fn, ok := table[c.ID]; ok {
			return fn(e)
		}
		// Unmapped, non-scored controls are manual reviews; scored ones would be
		// a coverage gap (the runner turns Unknown into INFO either way).
		return compliance.Assessment{Status: compliance.StatusInfo,
			Evidence: "manual control; no automated check"}
	}
}

// Assess runs the full CIS Docker Benchmark against the evidence and returns the
// aggregated report. This is the single entry point used by both the module's
// Analyze and the `dsecrat bench docker` command.
func Assess(e *Evidence) *compliance.Report {
	b := Benchmark()
	return b.Run(checksFor(e))
}
