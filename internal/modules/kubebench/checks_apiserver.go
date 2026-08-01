package kubebench

import (
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/compliance"
)

// --- Section 1 checks: control-plane / API server --------------------------
//
// Control-plane checks read the API server's effective flags. When those flags
// were not collected (e.g. a snapshot that omitted the control plane) the check
// degrades to INFO — distinct from the profile-level "provider-managed" INFO
// that the dispatcher applies on managed clusters.

// noAPIServer guards apiserver checks when no flags were collected.
func (e *Evidence) noAPIServer() (compliance.Assessment, bool) {
	if !e.APIServer.hasFlags() {
		return info("kube-apiserver flags not collected; cannot assess"), true
	}
	return compliance.Assessment{}, false
}

// flagIsFalse asserts a boolean flag is explicitly "false".
func flagIsFalse(c Component, name string) bool {
	v, ok := c.flag(name)
	return ok && strings.EqualFold(v, "false")
}

// flagIsTrue asserts a boolean flag is explicitly "true".
func flagIsTrue(c Component, name string) bool {
	v, ok := c.flag(name)
	return ok && strings.EqualFold(v, "true")
}

// listContains reports whether a comma-separated flag includes value (case-insensitive).
func listContains(c Component, name, value string) bool {
	for _, item := range c.flagList(name) {
		if strings.EqualFold(strings.TrimSpace(item), value) {
			return true
		}
	}
	return false
}

func check121AnonymousAuth(e *Evidence) compliance.Assessment {
	if a, skip := e.noAPIServer(); skip {
		return a
	}
	if flagIsFalse(e.APIServer, "anonymous-auth") {
		return pass("--anonymous-auth=false")
	}
	v, _ := e.APIServer.flag("anonymous-auth")
	return fail("anonymous requests to the API server are not disabled", orNA(v))
}

func check122TokenAuthFile(e *Evidence) compliance.Assessment {
	if a, skip := e.noAPIServer(); skip {
		return a
	}
	if v, ok := e.APIServer.flag("token-auth-file"); ok {
		return fail("static token auth file is configured", v)
	}
	return pass("--token-auth-file is not set")
}

func check126AuthzNotAlwaysAllow(e *Evidence) compliance.Assessment {
	if a, skip := e.noAPIServer(); skip {
		return a
	}
	if listContains(e.APIServer, "authorization-mode", "AlwaysAllow") {
		return fail("authorization-mode includes AlwaysAllow", flagOrNA(e.APIServer, "authorization-mode"))
	}
	if !e.APIServer.present("authorization-mode") {
		return warn("authorization-mode not explicitly set", "unset")
	}
	return pass("authorization-mode does not include AlwaysAllow")
}

func check127AuthzNode(e *Evidence) compliance.Assessment {
	return requireAuthzMode(e, "Node")
}

func check128AuthzRBAC(e *Evidence) compliance.Assessment {
	return requireAuthzMode(e, "RBAC")
}

func requireAuthzMode(e *Evidence, mode string) compliance.Assessment {
	if a, skip := e.noAPIServer(); skip {
		return a
	}
	if listContains(e.APIServer, "authorization-mode", mode) {
		return pass("authorization-mode includes " + mode)
	}
	return fail("authorization-mode does not include "+mode, flagOrNA(e.APIServer, "authorization-mode"))
}

func check1211NoAlwaysAdmit(e *Evidence) compliance.Assessment {
	if a, skip := e.noAPIServer(); skip {
		return a
	}
	if listContains(e.APIServer, "enable-admission-plugins", "AlwaysAdmit") {
		return fail("AlwaysAdmit admission plugin is enabled", flagOrNA(e.APIServer, "enable-admission-plugins"))
	}
	return pass("AlwaysAdmit admission plugin is not enabled")
}

func check1216NodeRestriction(e *Evidence) compliance.Assessment {
	if a, skip := e.noAPIServer(); skip {
		return a
	}
	if listContains(e.APIServer, "enable-admission-plugins", "NodeRestriction") {
		return pass("NodeRestriction admission plugin is enabled")
	}
	return fail("NodeRestriction admission plugin is not enabled", flagOrNA(e.APIServer, "enable-admission-plugins"))
}

func check1219Profiling(e *Evidence) compliance.Assessment {
	if a, skip := e.noAPIServer(); skip {
		return a
	}
	if flagIsFalse(e.APIServer, "profiling") {
		return pass("--profiling=false")
	}
	return fail("API server profiling endpoint is not disabled", flagOrNA(e.APIServer, "profiling"))
}

func check1222AuditLog(e *Evidence) compliance.Assessment {
	if a, skip := e.noAPIServer(); skip {
		return a
	}
	if v, ok := e.APIServer.flag("audit-log-path"); ok && v != "" {
		return pass("audit log path configured")
	}
	return fail("API server audit logging is not configured", "unset")
}

func check1231Encryption(e *Evidence) compliance.Assessment {
	if a, skip := e.noAPIServer(); skip {
		return a
	}
	if v, ok := e.APIServer.flag("encryption-provider-config"); ok && v != "" {
		return pass("encryption-at-rest provider configured")
	}
	return fail("Secrets are not encrypted at rest (no encryption-provider-config)", "unset")
}

// --- Section 1.1 file-permission checks ------------------------------------

func check111APIServerPerms(e *Evidence) compliance.Assessment {
	return checkPermsAtMost(e, "/etc/kubernetes/manifests/kube-apiserver.yaml", 0o600)
}

func check112APIServerOwner(e *Evidence) compliance.Assessment {
	return checkOwnership(e, "/etc/kubernetes/manifests/kube-apiserver.yaml", "root", "root")
}

// orNA renders an empty flag value as "unset".
func orNA(v string) string {
	if v == "" {
		return "unset"
	}
	return v
}

// flagOrNA renders a component flag or "unset".
func flagOrNA(c Component, name string) string {
	if v, ok := c.flag(name); ok {
		return orNA(v)
	}
	return "unset"
}
