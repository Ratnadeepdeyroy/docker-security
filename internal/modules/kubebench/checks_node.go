package kubebench

import "github.com/Ratnadeepdeyroy/docker-security/internal/compliance"

// --- Section 4 checks: worker node (kubelet) -------------------------------
//
// The kubelet is the node's control point; a weak kubelet API is a direct path
// to code execution in every pod on that node. Checks read kubelet flags (a
// collector normalizes config-file settings into the same flag map). Uncollected
// flags degrade to INFO.

func (e *Evidence) noKubelet() (compliance.Assessment, bool) {
	if !e.Kubelet.hasFlags() {
		return info("kubelet configuration not collected; cannot assess"), true
	}
	return compliance.Assessment{}, false
}

func check419KubeletConfigPerms(e *Evidence) compliance.Assessment {
	return checkPermsAtMost(e, "/var/lib/kubelet/config.yaml", 0o600)
}

func check421KubeletAnonAuth(e *Evidence) compliance.Assessment {
	if a, skip := e.noKubelet(); skip {
		return a
	}
	if flagIsFalse(e.Kubelet, "anonymous-auth") {
		return pass("kubelet --anonymous-auth=false")
	}
	return fail("kubelet allows anonymous authentication", flagOrNA(e.Kubelet, "anonymous-auth"))
}

func check422KubeletAuthz(e *Evidence) compliance.Assessment {
	if a, skip := e.noKubelet(); skip {
		return a
	}
	mode, ok := e.Kubelet.flag("authorization-mode")
	if ok && mode == "AlwaysAllow" {
		return fail("kubelet authorization-mode is AlwaysAllow", mode)
	}
	if !ok {
		return warn("kubelet authorization-mode not explicitly set", "unset")
	}
	return pass("kubelet authorization-mode is not AlwaysAllow")
}

func check423KubeletClientCA(e *Evidence) compliance.Assessment {
	if a, skip := e.noKubelet(); skip {
		return a
	}
	if v, ok := e.Kubelet.flag("client-ca-file"); ok && v != "" {
		return pass("kubelet client CA file is configured")
	}
	return fail("kubelet has no client CA file (cannot verify API-server certs)", "unset")
}

func check424KubeletReadOnlyPort(e *Evidence) compliance.Assessment {
	if a, skip := e.noKubelet(); skip {
		return a
	}
	v, ok := e.Kubelet.flag("read-only-port")
	if !ok || v == "0" {
		return pass("kubelet read-only port is disabled")
	}
	return fail("kubelet read-only port is enabled (unauthenticated node/pod data)", v)
}

func check425KubeletStreamingTimeout(e *Evidence) compliance.Assessment {
	if a, skip := e.noKubelet(); skip {
		return a
	}
	v, ok := e.Kubelet.flag("streaming-connection-idle-timeout")
	if ok && v == "0" {
		return fail("kubelet streaming connection idle timeout is 0 (never times out)", "0")
	}
	return pass("kubelet streaming connection idle timeout is non-zero")
}

func check426KubeletIPTables(e *Evidence) compliance.Assessment {
	if a, skip := e.noKubelet(); skip {
		return a
	}
	v, ok := e.Kubelet.flag("make-iptables-util-chains")
	if !ok || v == "true" {
		return pass("kubelet manages iptables util chains (default)")
	}
	return fail("kubelet is not managing iptables util chains", v)
}

func check429KubeletCertRotation(e *Evidence) compliance.Assessment {
	if a, skip := e.noKubelet(); skip {
		return a
	}
	if flagIsTrue(e.Kubelet, "rotate-server-certificates") || flagIsTrue(e.Kubelet, "RotateKubeletServerCertificate") {
		return pass("kubelet server certificate rotation is enabled")
	}
	return warn("kubelet server certificate rotation is not enabled", "unset")
}
