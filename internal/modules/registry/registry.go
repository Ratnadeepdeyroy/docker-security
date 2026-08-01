// Package registry implements the registry-security & artifact-management
// capability (CAPABILITY_SPEC domain 13). Where the verify module (domain 9)
// proves that a signature/attestation is valid, this module audits the *trust
// posture* of the registry an artifact is pulled from: is it an allowlisted,
// private source; is the pull pinned to an immutable digest; is the connection
// plaintext; does the image name look like a typosquat of a popular one.
//
// It is deterministic and offline: every check reasons over image references
// extracted from the target (Dockerfile FROM lines, an image ref, or a registry
// target) plus optional policy supplied through the target Metadata. It reads
// neither the wall clock nor the network, so the same inputs always yield the
// same findings — the golden path the tests pin.
//
// Configuration travels via the target Metadata so the module stays a pure
// function of its inputs:
//
//	registry.allow      comma-separated trusted registry hosts (enables allowlist mode)
//	registry.insecure   comma-separated hosts known to be served over plaintext HTTP
//
// With no allowlist configured the module runs in advisory mode: it recommends
// pinning, an allowlist, and a private/pull-through source rather than failing a
// build outright.
package registry

import (
	"context"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/dockerfile"
	"github.com/Ratnadeepdeyroy/docker-security/internal/registry"
)

const moduleName = "registry"

// Module is the registry-security posture capability.
type Module struct{}

// New returns a registry-security module.
func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "Registry security & artifact management: trusted-registry allowlist, digest pinning, insecure-registry & typosquat detection (domain 13)"
}
func (m *Module) Domains() []string { return []string{"13"} }

// Supports the three target kinds that carry an image reference: a Dockerfile
// (its FROM base images), a built image, and a registry reference.
func (m *Module) Supports(t engine.TargetType) bool {
	return t == engine.TargetDockerfile || t == engine.TargetImage || t == engine.TargetRegistry
}

// imageRef is one reference to audit plus where it came from, so a finding can
// point back at a Dockerfile line when the source was a Dockerfile.
type imageRef struct {
	raw      string // the reference exactly as written
	ref      registry.Reference
	location *engine.Location // non-nil only for Dockerfile FROM lines
}

// Analyze collects the image references the target pulls from and runs the
// registry-posture checks against each.
func (m *Module) Analyze(_ context.Context, t *engine.Target) ([]engine.Finding, error) {
	cfg := parsePolicy(t.Metadata)
	refs := collectRefs(t)

	var findings []engine.Finding
	for _, ir := range refs {
		findings = append(findings, checkRef(ir, cfg)...)
	}
	sortFindings(findings)
	return findings, nil
}

// policy holds the operator-supplied trust configuration for a run.
type policy struct {
	allow    map[string]bool // trusted registry hosts; empty => advisory mode
	insecure map[string]bool // hosts explicitly known to be plaintext HTTP
}

func (p policy) allowlistMode() bool { return len(p.allow) > 0 }

func parsePolicy(md map[string]string) policy {
	return policy{
		allow:    hostSet(md["registry.allow"]),
		insecure: hostSet(md["registry.insecure"]),
	}
}

// hostSet splits a comma-separated host list into a lowercase lookup set.
func hostSet(s string) map[string]bool {
	out := map[string]bool{}
	for _, h := range strings.Split(s, ",") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			out[h] = true
		}
	}
	return out
}

// collectRefs gathers every image reference the target depends on.
func collectRefs(t *engine.Target) []imageRef {
	switch t.Type {
	case engine.TargetDockerfile:
		return dockerfileRefs(t)
	case engine.TargetImage:
		return imageTargetRefs(t)
	case engine.TargetRegistry:
		if r := parseRaw(strings.TrimSpace(t.Location)); r != nil {
			return []imageRef{*r}
		}
	}
	return nil
}

// dockerfileRefs extracts base-image references from FROM instructions, skipping
// `scratch` and FROM lines that reference an earlier build stage by name.
func dockerfileRefs(t *engine.Target) []imageRef {
	df := dockerfile.Parse(string(t.Content))
	stages := map[string]bool{}
	var out []imageRef
	for _, ins := range df.From() {
		fields := strings.Fields(ins.Args)
		if len(fields) == 0 {
			continue
		}
		image := stripScheme(fields[0])
		// Record the stage alias (FROM x AS name) so later `FROM name` is skipped.
		alias := ""
		if len(fields) >= 3 && strings.EqualFold(fields[1], "AS") {
			alias = strings.ToLower(fields[2])
		}
		lowerImg := strings.ToLower(image)
		if lowerImg == "scratch" || stages[lowerImg] {
			if alias != "" {
				stages[alias] = true
			}
			continue
		}
		if alias != "" {
			stages[alias] = true
		}
		if strings.HasPrefix(image, "$") { // ARG-templated base; can't resolve statically
			continue
		}
		loc := &engine.Location{Path: t.Location, StartLine: ins.StartLine, EndLine: ins.EndLine}
		if r := parseRawAt(fields[0], loc); r != nil {
			out = append(out, *r)
		}
	}
	return out
}

// imageTargetRefs resolves the reference for a built-image target from its
// metadata (the `docker.ref` the server records when saving a local image),
// falling back to the load location.
func imageTargetRefs(t *engine.Target) []imageRef {
	raw := ""
	if t.Metadata != nil {
		raw = t.Metadata["docker.ref"]
	}
	if raw == "" {
		raw = t.Location
	}
	if r := parseRaw(strings.TrimSpace(raw)); r != nil {
		return []imageRef{*r}
	}
	return nil
}

// parseRaw parses a reference with no source location.
func parseRaw(raw string) *imageRef { return parseRawAt(raw, nil) }

// parseRawAt parses a reference, attaching a source location. It returns nil for
// anything that does not parse as an image reference (e.g. a local tar path),
// so filesystem image archives passed as a target location are ignored rather
// than mis-reported.
func parseRawAt(raw string, loc *engine.Location) *imageRef {
	clean := stripScheme(raw)
	if clean == "" || looksLikePath(clean) {
		return nil
	}
	ref, err := registry.ParseReference(clean)
	if err != nil {
		return nil
	}
	return &imageRef{raw: raw, ref: ref, location: loc}
}

// stripScheme removes a leading http:// or https:// so a plaintext reference
// still parses; the scheme is remembered separately by the insecure check.
func stripScheme(s string) string {
	for _, p := range []string{"http://", "https://"} {
		if strings.HasPrefix(strings.ToLower(s), p) {
			return s[len(p):]
		}
	}
	return s
}

// looksLikePath reports whether a string is a local filesystem path (a saved
// image tar / OCI layout) rather than a registry reference.
func looksLikePath(s string) bool {
	if strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") {
		return true
	}
	for _, ext := range []string{".tar", ".tar.gz", ".tgz", ".oci"} {
		if strings.HasSuffix(strings.ToLower(s), ext) {
			return true
		}
	}
	return false
}

// sortFindings gives a stable order (rule id, then resource, then line) so the
// golden tests can pin output independent of the engine's later severity sort.
func sortFindings(fs []engine.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].RuleID != fs[j].RuleID {
			return fs[i].RuleID < fs[j].RuleID
		}
		if fs[i].Resource != fs[j].Resource {
			return fs[i].Resource < fs[j].Resource
		}
		li, lj := 0, 0
		if fs[i].Location != nil {
			li = fs[i].Location.StartLine
		}
		if fs[j].Location != nil {
			lj = fs[j].Location.StartLine
		}
		return li < lj
	})
}
