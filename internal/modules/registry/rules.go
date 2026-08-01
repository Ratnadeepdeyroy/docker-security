package registry

import (
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/registry"
)

// Rule IDs, namespaced DS-RAT-REG-* (domain 13).
const (
	ruleMutableTag   = "DS-RAT-REG-001" // pulled by mutable tag, not immutable digest
	ruleUntrusted    = "DS-RAT-REG-002" // registry not on the trusted allowlist
	ruleInsecure     = "DS-RAT-REG-003" // plaintext HTTP registry connection
	ruleTyposquat    = "DS-RAT-REG-004" // image name looks like a typosquat of a popular image
	rulePublicSource = "DS-RAT-REG-005" // dependency on a public registry (advisory)
)

// checkRef runs every posture check against one reference.
func checkRef(ir imageRef, cfg policy) []engine.Finding {
	var fs []engine.Finding
	if f, ok := checkInsecure(ir, cfg); ok {
		fs = append(fs, f)
	}
	if f, ok := checkTrust(ir, cfg); ok {
		fs = append(fs, f)
	}
	if f, ok := checkMutableTag(ir); ok {
		fs = append(fs, f)
	}
	if f, ok := checkTyposquat(ir); ok {
		fs = append(fs, f)
	}
	return fs
}

// checkInsecure flags a reference served over plaintext HTTP — either an
// explicit http:// scheme or a host the operator listed in registry.insecure.
// Plaintext registry traffic can be MITM'd to swap image bytes or steal the
// pull credential.
func checkInsecure(ir imageRef, cfg policy) (engine.Finding, bool) {
	http := strings.HasPrefix(strings.ToLower(ir.raw), "http://")
	listed := cfg.insecure[strings.ToLower(ir.ref.Registry)]
	if !http && !listed {
		return engine.Finding{}, false
	}
	return finding(ruleInsecure, engine.SeverityHigh, ir,
		"Image pulled from an insecure (plaintext HTTP) registry",
		"The registry "+ir.ref.Registry+" is accessed over plaintext HTTP; a network attacker can tamper with image bytes in transit or capture the pull credential.",
		"Serve the registry over TLS and remove it from any insecure-registries allowlist; require HTTPS for all pulls.",
		"https://docs.docker.com/reference/cli/dockerd/#insecure-registries"), true
}

// checkTrust enforces the trusted-registry allowlist when one is configured. In
// advisory mode (no allowlist) it instead recommends locking pulls to a private
// or pull-through source when the reference targets a public registry.
func checkTrust(ir imageRef, cfg policy) (engine.Finding, bool) {
	host := strings.ToLower(ir.ref.Registry)
	if cfg.allowlistMode() {
		if cfg.allow[host] {
			return engine.Finding{}, false
		}
		return finding(ruleUntrusted, engine.SeverityHigh, ir,
			"Image pulled from a registry not on the trusted allowlist",
			"The registry "+ir.ref.Registry+" is not in the configured trusted-registry allowlist; sideloaded or typosquatted sources can inject backdoored images.",
			"Pull only from allowlisted registries, or add this host to registry.allow if it is genuinely trusted. Enforce the allowlist at admission (e.g. a ValidatingWebhook).",
			"https://kyverno.io/policies/other/restrict-image-registries/"), true
	}
	if isPublicRegistry(host) {
		return finding(rulePublicSource, engine.SeverityLow, ir,
			"Dependency on a public registry",
			"This image is pulled from the public registry "+ir.ref.Registry+". Public sources add exposure to rate limits, takedowns, and upstream compromise.",
			"Mirror the image into a private or pull-through-cache registry, scan on push, and enforce a trusted-registry allowlist (set registry.allow).",
			"https://www.paloaltonetworks.com/cyberpedia/container-registry-security"), true
	}
	return engine.Finding{}, false
}

// checkMutableTag flags a pull that is not pinned to an immutable digest. A
// mutable tag can be overwritten in the registry, which defeats the guarantee a
// signed digest gives you (verify, domain 9) and enables cache-poisoning.
func checkMutableTag(ir imageRef) (engine.Finding, bool) {
	if ir.ref.Digest != "" {
		return engine.Finding{}, false
	}
	return finding(ruleMutableTag, engine.SeverityMedium, ir,
		"Image pulled by mutable tag, not by immutable digest",
		"The reference "+ir.ref.String()+" resolves by tag; the tag can be repointed to different bytes after signing/scanning (tag-swap, cache poisoning).",
		"Pin the reference to an immutable digest (image@sha256:...), and enforce tag immutability in the registry so published tags cannot be overwritten.",
		"https://kyverno.io/policies/other/require-image-checksum/"), true
}

// checkTyposquat flags a repository whose final path segment is one edit away
// from a popular official image, which is the shape of a typosquat or a
// dependency-confusion attack (a look-alike published under a different
// namespace or registry). An exact popular name published under a non-official
// namespace is flagged too.
func checkTyposquat(ir imageRef) (engine.Finding, bool) {
	base := ir.ref.Repository
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	base = strings.ToLower(base)
	official := isDockerHub(ir.ref.Registry) && strings.HasPrefix(ir.ref.Repository, "library/")

	if popularImages[base] {
		if official {
			return engine.Finding{}, false // the genuine official image
		}
		return finding(ruleTyposquat, engine.SeverityMedium, ir,
			"Popular image name published under a non-official namespace",
			"The name \""+base+"\" matches a popular official image but is served from "+ir.ref.String()+", not the official library. This is the shape of a dependency-confusion / name-squat attack.",
			"Confirm the publisher is trusted; prefer the official image (docker.io/library/"+base+") or an internally vetted mirror, pinned by digest.",
			"https://www.paloaltonetworks.com/cyberpedia/container-registry-security"), true
	}
	for name := range popularImages {
		if len(base) >= 4 && editDistance1(base, name) {
			return finding(ruleTyposquat, engine.SeverityMedium, ir,
				"Image name closely resembles a popular image (possible typosquat)",
				"The name \""+base+"\" is one character away from the popular image \""+name+"\"; typosquatted names resolve to attacker-published images.",
				"Verify the intended image name and publisher; pin the trusted image by digest and enforce a registry/name allowlist.",
				"https://kyverno.io/policies/other/restrict-image-registries/"), true
		}
	}
	return engine.Finding{}, false
}

// isPublicRegistry reports whether a host is a well-known public registry.
func isPublicRegistry(host string) bool { return publicRegistries[host] }

// isDockerHub reports whether a host is one of Docker Hub's aliases, all of
// which serve the same `library/` official namespace.
func isDockerHub(host string) bool {
	switch strings.ToLower(host) {
	case registry.DefaultRegistry, "docker.io", "index.docker.io", "registry.hub.docker.com":
		return true
	}
	return false
}

var publicRegistries = map[string]bool{
	registry.DefaultRegistry: true,
	"docker.io":              true,
	"index.docker.io":        true,
	"ghcr.io":                true,
	"quay.io":                true,
	"gcr.io":                 true,
	"public.ecr.aws":         true,
	"mcr.microsoft.com":      true,
	"registry.k8s.io":        true,
}

// popularImages is a conservative set of widely-pulled official image names, the
// targets a typosquat would imitate.
var popularImages = map[string]bool{
	"alpine": true, "ubuntu": true, "debian": true, "busybox": true,
	"nginx": true, "httpd": true, "node": true, "python": true,
	"golang": true, "openjdk": true, "redis": true, "postgres": true,
	"mysql": true, "mariadb": true, "mongo": true, "centos": true,
	"fedora": true, "rabbitmq": true, "memcached": true, "traefik": true,
}

// editDistance1 reports whether a and b differ by exactly one single-character
// edit (substitution, insertion, or deletion). It is a bounded, allocation-free
// check — cheaper and more precise for typosquat detection than a full
// Levenshtein matrix, since anything further than one edit is not a squat.
func editDistance1(a, b string) bool {
	if a == b {
		return false
	}
	la, lb := len(a), len(b)
	if la-lb > 1 || lb-la > 1 {
		return false
	}
	if la == lb { // one substitution
		diff := 0
		for i := 0; i < la; i++ {
			if a[i] != b[i] {
				diff++
			}
		}
		return diff == 1
	}
	// Lengths differ by one: one insertion/deletion. Walk both, allowing a
	// single skip in the longer string.
	if la > lb {
		a, b = b, a // ensure b is the longer
	}
	i, j, skips := 0, 0, 0
	for i < len(a) && j < len(b) {
		if a[i] == b[j] {
			i++
			j++
			continue
		}
		skips++
		if skips > 1 {
			return false
		}
		j++ // skip one char in the longer string
	}
	return true
}

// finding builds a DS-RAT-REG finding with the module identity and reference
// context pre-filled.
func finding(id string, sev engine.Severity, ir imageRef, title, desc, remediation string, refs ...string) engine.Finding {
	return engine.Finding{
		RuleID:      id,
		Module:      moduleName,
		Severity:    sev,
		Title:       title,
		Description: desc,
		Remediation: remediation,
		Resource:    ir.ref.String(),
		Location:    ir.location,
		References:  refs,
	}
}
