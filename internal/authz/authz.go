// Package authz implements a Docker daemon authorization plugin
// (CAPABILITY_SPEC domain 8 / 15). For standalone Docker there is no API server
// to run an admission controller, so the daemon's AuthZ plugin framework is the
// only enforceable gate on dangerous API calls. This package evaluates each
// proxied Docker API request against a policy and returns allow/deny using the
// exact wire contract Docker expects, so `dockerd --authorization-plugin` can
// point at it.
//
// The policy engine is pure and table-driven — Evaluate maps a (method, path,
// parsed body) to a Decision with no I/O — so it is golden-testable; the HTTP
// server is a thin adapter over it (see server.go).
package authz

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Request is the subset of Docker's AuthZReq we reason about. Docker sends more
// fields; we decode only what a policy needs. RequestBody is base64 in the wire
// message; the server decodes it before calling Evaluate.
type Request struct {
	Method string // HTTP method, e.g. "POST"
	URI    string // request URI incl. query, e.g. "/v1.43/containers/create"
	Body   []byte // decoded request body (may be nil for GETs)
}

// Decision is the plugin's verdict.
type Decision struct {
	Allow bool
	// Msg is shown to the Docker user on allow; Reason explains a deny.
	Msg    string
	Reason string
	// Rule is the id of the policy rule that decided (for logging/audit).
	Rule string
}

// Policy configures which dangerous operations to deny. Every field defaults to
// the safe-but-permissive off, so an empty policy allows everything (a no-op
// plugin); operators opt into each guardrail.
type Policy struct {
	// DenyPrivileged denies `POST /containers/create` (and run) with
	// HostConfig.Privileged=true.
	DenyPrivileged bool
	// DenyHostNamespaces denies host PID/IPC/Network/UTS namespace sharing.
	DenyHostNamespaces bool
	// DenyHostPathMounts denies bind-mounting sensitive host paths (see
	// SensitiveHostPaths); DenyDockerSocketMount is the most important special
	// case and is implied when this is set.
	DenyHostPathMounts bool
	// DenyDockerSocketMount denies mounting /var/run/docker.sock into a container
	// (host-root-equivalent), even when general host-path mounts are allowed.
	DenyDockerSocketMount bool
	// DenyCapAdd denies adding any capability in this set (case-insensitive,
	// with or without the CAP_ prefix), e.g. SYS_ADMIN, NET_ADMIN.
	DenyCapAdd []string
	// ReadOnly denies all mutating API calls (POST/PUT/DELETE), turning the
	// daemon into a read-only endpoint. Useful for locked-down hosts.
	ReadOnly bool

	denyCaps map[string]bool
}

func (p *Policy) index() {
	if p.denyCaps != nil {
		return
	}
	p.denyCaps = map[string]bool{}
	for _, c := range p.DenyCapAdd {
		p.denyCaps[normalizeCap(c)] = true
	}
}

// SensitiveHostPaths are host locations whose bind-mount into a container is a
// container-to-host escape or credential-theft vector.
var SensitiveHostPaths = []string{
	"/", "/etc", "/var/run", "/run", "/proc", "/sys", "/dev",
	"/var/lib/docker", "/root", "/home",
}

// dockerSocketPaths are the daemon-socket locations that equal host root.
var dockerSocketPaths = []string{
	"/var/run/docker.sock", "/run/docker.sock",
}

// createPathRe matches the container-create endpoint across API versions
// (/v1.43/containers/create, /containers/create).
var createPathRe = regexp.MustCompile(`/(v[0-9.]+/)?containers/create$`)

// Evaluate returns the plugin decision for a request. Allow-by-default: only a
// matched deny rule blocks. The first matching deny wins and names itself.
func (p *Policy) Evaluate(req Request) Decision {
	p.index()

	if p.ReadOnly && isMutating(req.Method) {
		return deny("AUTHZ-READONLY", "daemon is in read-only mode; mutating API calls are denied")
	}

	// Only container-create carries the HostConfig we inspect.
	if strings.EqualFold(req.Method, "POST") && createPathRe.MatchString(pathOnly(req.URI)) {
		if d, blocked := p.evalCreate(req.Body); blocked {
			return d
		}
	}
	return allow("request permitted by policy")
}

// createRequest is the slice of the container-create body a policy inspects.
type createRequest struct {
	HostConfig struct {
		Privileged  bool     `json:"Privileged"`
		NetworkMode string   `json:"NetworkMode"`
		PidMode     string   `json:"PidMode"`
		IpcMode     string   `json:"IpcMode"`
		UTSMode     string   `json:"UTSMode"`
		Binds       []string `json:"Binds"`
		CapAdd      []string `json:"CapAdd"`
		Mounts      []struct {
			Source string `json:"Source"`
			Type   string `json:"Type"`
		} `json:"Mounts"`
	} `json:"HostConfig"`
}

func (p *Policy) evalCreate(body []byte) (Decision, bool) {
	var c createRequest
	if len(body) > 0 {
		// A body we cannot parse is treated as empty rather than failing open on a
		// specific rule; the daemon rejects truly malformed bodies itself.
		_ = json.Unmarshal(body, &c)
	}

	if p.DenyPrivileged && c.HostConfig.Privileged {
		return deny("AUTHZ-PRIVILEGED", "privileged containers are not permitted"), true
	}

	if p.DenyHostNamespaces {
		for name, mode := range map[string]string{
			"network": c.HostConfig.NetworkMode,
			"pid":     c.HostConfig.PidMode,
			"ipc":     c.HostConfig.IpcMode,
			"uts":     c.HostConfig.UTSMode,
		} {
			if strings.EqualFold(mode, "host") {
				return deny("AUTHZ-HOSTNS", "sharing the host "+name+" namespace is not permitted"), true
			}
		}
	}

	// Collect every host source path from both Binds and Mounts.
	var sources []string
	for _, b := range c.HostConfig.Binds {
		sources = append(sources, hostSrcFromBind(b))
	}
	for _, m := range c.HostConfig.Mounts {
		if m.Type == "" || strings.EqualFold(m.Type, "bind") {
			sources = append(sources, m.Source)
		}
	}
	for _, src := range sources {
		if (p.DenyDockerSocketMount || p.DenyHostPathMounts) && isDockerSocket(src) {
			return deny("AUTHZ-DOCKERSOCK", "mounting the Docker daemon socket is not permitted (host-root equivalent)"), true
		}
		if p.DenyHostPathMounts && isSensitiveHostPath(src) {
			return deny("AUTHZ-HOSTPATH", "bind-mounting sensitive host path "+src+" is not permitted"), true
		}
	}

	for _, cap := range c.HostConfig.CapAdd {
		if p.denyCaps[normalizeCap(cap)] {
			return deny("AUTHZ-CAPADD", "adding capability "+cap+" is not permitted"), true
		}
	}
	return Decision{}, false
}

// --- helpers ---------------------------------------------------------------

func isMutating(method string) bool {
	switch strings.ToUpper(method) {
	case "POST", "PUT", "DELETE", "PATCH":
		return true
	default:
		return false
	}
}

func pathOnly(uri string) string {
	if i := strings.IndexByte(uri, '?'); i >= 0 {
		return uri[:i]
	}
	return uri
}

// hostSrcFromBind extracts the host source of a "src:dst[:opts]" bind string.
func hostSrcFromBind(b string) string {
	if i := strings.IndexByte(b, ':'); i >= 0 {
		return b[:i]
	}
	return b
}

func isDockerSocket(src string) bool {
	src = strings.TrimRight(src, "/")
	for _, s := range dockerSocketPaths {
		if src == s {
			return true
		}
	}
	return false
}

func isSensitiveHostPath(src string) bool {
	src = strings.TrimRight(src, "/")
	if src == "" {
		src = "/"
	}
	for _, p := range SensitiveHostPaths {
		if src == p || strings.HasPrefix(src, p+"/") {
			return true
		}
	}
	return src == "/"
}

func normalizeCap(c string) string {
	c = strings.ToUpper(strings.TrimSpace(c))
	return strings.TrimPrefix(c, "CAP_")
}

func allow(msg string) Decision { return Decision{Allow: true, Msg: msg} }
func deny(rule, reason string) Decision {
	return Decision{Allow: false, Reason: reason, Rule: rule}
}
