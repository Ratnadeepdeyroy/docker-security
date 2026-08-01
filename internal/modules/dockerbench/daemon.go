package dockerbench

import (
	"fmt"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/compliance"
)

// --- Section 2 checks: Docker daemon configuration -------------------------
//
// Each function assesses one control from the daemon.json / docker-info
// evidence. They are pure: same Evidence in, same Assessment out. When the
// relevant input was not collected they return INFO ("unknown"), never fail.

// pass/warn/fail/info are terse Assessment constructors that keep the checks
// below readable.
func pass(evidence string) compliance.Assessment {
	return compliance.Assessment{Status: compliance.StatusPass, Evidence: evidence}
}
func warn(evidence, actual string) compliance.Assessment {
	return compliance.Assessment{Status: compliance.StatusWarn, Evidence: evidence, Actual: actual}
}
func fail(evidence, actual string) compliance.Assessment {
	return compliance.Assessment{Status: compliance.StatusFail, Evidence: evidence, Actual: actual}
}
func info(evidence string) compliance.Assessment {
	return compliance.Assessment{Status: compliance.StatusInfo, Evidence: evidence}
}

// noDaemon guards daemon checks: if daemon.json was never collected there is
// nothing to assess, so degrade to INFO.
func (e *Evidence) noDaemon() (compliance.Assessment, bool) {
	if e.Daemon == nil {
		return info("daemon.json not collected; cannot assess"), true
	}
	return compliance.Assessment{}, false
}

func check21ICC(e *Evidence) compliance.Assessment {
	if a, skip := e.noDaemon(); skip {
		return a
	}
	val, present := e.daemonBool("icc")
	if present && !val {
		return pass(`"icc" is false; inter-container comms restricted on the default bridge`)
	}
	return warn(`inter-container communication is not disabled (icc defaults to true)`, fmt.Sprintf("icc=%v", val))
}

func check22LogLevel(e *Evidence) compliance.Assessment {
	if a, skip := e.noDaemon(); skip {
		return a
	}
	lvl, present := e.daemonString("log-level")
	if !present || lvl == "info" {
		return pass(`log level is 'info' (default or explicit)`)
	}
	return warn(fmt.Sprintf("log level is %q, not 'info'", lvl), lvl)
}

func check23Iptables(e *Evidence) compliance.Assessment {
	if a, skip := e.noDaemon(); skip {
		return a
	}
	val, present := e.daemonBool("iptables")
	if present && !val {
		return fail(`"iptables": false disables daemon-managed firewall rules`, "iptables=false")
	}
	return pass("daemon manages iptables (default)")
}

func check24InsecureRegistries(e *Evidence) compliance.Assessment {
	if a, skip := e.noDaemon(); skip {
		return a
	}
	regs, present := e.daemonStrings("insecure-registries")
	if !present || len(regs) == 0 {
		return pass("no insecure registries configured")
	}
	return fail("insecure (plaintext) registries are configured", strings.Join(regs, ","))
}

func check25StorageDriver(e *Evidence) compliance.Assessment {
	if a, skip := e.noDaemon(); skip {
		return a
	}
	drv, _ := e.daemonString("storage-driver")
	if drv == "" {
		drv = e.Info.StorageDriver
	}
	if strings.EqualFold(drv, "aufs") {
		return fail("deprecated aufs storage driver in use", drv)
	}
	return pass(fmt.Sprintf("storage driver %q is not aufs", orDefault(drv, "default")))
}

func check26TLS(e *Evidence) compliance.Assessment {
	if a, skip := e.noDaemon(); skip {
		return a
	}
	hosts, _ := e.daemonStrings("hosts")
	tcp := false
	for _, h := range hosts {
		if strings.HasPrefix(h, "tcp://") {
			tcp = true
		}
	}
	if !tcp {
		return pass("daemon is not exposed over TCP; TLS not required")
	}
	verify, _ := e.daemonBool("tlsverify")
	_, hasCA := e.daemonString("tlscacert")
	_, hasCert := e.daemonString("tlscert")
	_, hasKey := e.daemonString("tlskey")
	if verify && hasCA && hasCert && hasKey {
		return pass("TCP socket protected by mutual TLS")
	}
	return fail("daemon exposed over TCP without complete mutual-TLS configuration", strings.Join(hosts, ","))
}

func check28UsernsRemap(e *Evidence) compliance.Assessment {
	if a, skip := e.noDaemon(); skip {
		return a
	}
	remap, present := e.daemonString("userns-remap")
	if e.Info.Rootless {
		return pass("daemon runs rootless; user-namespace isolation in effect")
	}
	if present && remap != "" && remap != "false" {
		return pass(fmt.Sprintf("user-namespace remapping enabled (%q)", remap))
	}
	return warn("user-namespace remapping is not enabled", "userns-remap unset")
}

func check211AuthzPlugin(e *Evidence) compliance.Assessment {
	if a, skip := e.noDaemon(); skip {
		return a
	}
	plugins, present := e.daemonStrings("authorization-plugins")
	if present && len(plugins) > 0 {
		return pass(fmt.Sprintf("authorization plugin(s) configured: %s", strings.Join(plugins, ",")))
	}
	return warn("no authorization plugin; every client has full daemon control", "authorization-plugins unset")
}

func check212RemoteLogging(e *Evidence) compliance.Assessment {
	if a, skip := e.noDaemon(); skip {
		return a
	}
	drv, present := e.daemonString("log-driver")
	if !present {
		drv = e.Info.LoggingDriver
	}
	switch drv {
	case "", "json-file", "local", "journald":
		return warn("logs are stored locally only; configure centralized/remote logging", orDefault(drv, "json-file"))
	default:
		return pass(fmt.Sprintf("remote log driver %q configured", drv))
	}
}

func check213LiveRestore(e *Evidence) compliance.Assessment {
	if a, skip := e.noDaemon(); skip {
		return a
	}
	val, present := e.daemonBool("live-restore")
	if (present && val) || e.Info.LiveRestore {
		return pass("live-restore is enabled")
	}
	return fail("live-restore is disabled; a daemon restart will kill running containers", "live-restore=false")
}

func check214UserlandProxy(e *Evidence) compliance.Assessment {
	if a, skip := e.noDaemon(); skip {
		return a
	}
	val, present := e.daemonBool("userland-proxy")
	if present && !val {
		return pass("userland proxy is disabled")
	}
	return warn("userland proxy is enabled (unnecessary data path)", "userland-proxy=true")
}

func check215Seccomp(e *Evidence) compliance.Assessment {
	if a, skip := e.noDaemon(); skip {
		return a
	}
	prof, _ := e.daemonString("seccomp-profile")
	if strings.EqualFold(prof, "unconfined") {
		return fail("daemon-wide seccomp profile is set to unconfined", prof)
	}
	return pass("default/custom seccomp profile is not disabled daemon-wide")
}

func check216Experimental(e *Evidence) compliance.Assessment {
	if a, skip := e.noDaemon(); skip {
		return a
	}
	val, present := e.daemonBool("experimental")
	if (present && val) || e.Info.Experimental {
		return fail("experimental daemon features are enabled", "experimental=true")
	}
	return pass("experimental features are not enabled")
}

func check217NoNewPrivs(e *Evidence) compliance.Assessment {
	if a, skip := e.noDaemon(); skip {
		return a
	}
	val, present := e.daemonBool("no-new-privileges")
	if present && val {
		return pass("no-new-privileges is the daemon-wide default")
	}
	return warn("containers may acquire new privileges by default", "no-new-privileges unset")
}

// orDefault returns fallback when s is empty.
func orDefault(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
