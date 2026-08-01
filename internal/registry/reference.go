// Package registry is a from-scratch OCI distribution (registry v2) client plus
// a small in-memory registry for offline tests and demos. It resolves image
// references, pulls and inspects manifests (Docker Schema 2 and OCI), and
// reads/writes OCI 1.1 referrers — the plumbing the supply-chain phase needs to
// attach and fetch signatures and attestations. It re-implements only the HTTP
// surface it uses (net/http, encoding/json); it depends on no container tooling.
//
// Network is strictly opt-in: nothing here dials out until a caller invokes a
// method that must, and every such method degrades gracefully (a clear error, no
// panic) when offline. All tests run against the in-memory MemoryRegistry, so
// the suite is fully hermetic.
package registry

import (
	"fmt"
	"strings"
)

// DefaultRegistry is the host assumed when a reference names none. It matches
// the Docker convention of resolving bare names against Docker Hub.
const DefaultRegistry = "registry-1.docker.io"

// DefaultTag is the tag assumed when a reference names neither tag nor digest.
const DefaultTag = "latest"

// Reference is a parsed image reference: registry host, repository path, and
// either a tag or a digest (or both, with digest taking precedence for pulls).
type Reference struct {
	// Registry is the host[:port] of the registry.
	Registry string
	// Repository is the full repository path (e.g. "library/alpine").
	Repository string
	// Tag is the human tag, if the reference had one ("" if digest-only).
	Tag string
	// Digest is the "sha256:<hex>" digest, if the reference pinned one.
	Digest string
}

// ParseReference parses a string like "registry:5000/team/app:1.2@sha256:...".
// It applies Docker's defaulting rules: a first path component that looks like a
// hostname (contains '.', ':', or is "localhost") is the registry; otherwise the
// reference targets the default registry and a bare name is prefixed with
// "library/". A reference with neither tag nor digest defaults to :latest.
func ParseReference(ref string) (Reference, error) {
	if strings.TrimSpace(ref) == "" {
		return Reference{}, fmt.Errorf("empty image reference")
	}
	remainder := ref

	// Split off a digest first: it is unambiguous (contains '@').
	var digest string
	if at := strings.Index(remainder, "@"); at >= 0 {
		digest = remainder[at+1:]
		remainder = remainder[:at]
		if err := validateDigest(digest); err != nil {
			return Reference{}, err
		}
	}

	// Decide whether the first slash-segment is a registry host.
	registry := DefaultRegistry
	name := remainder
	if slash := strings.Index(remainder, "/"); slash >= 0 {
		first := remainder[:slash]
		if looksLikeHost(first) {
			registry = first
			name = remainder[slash+1:]
		}
	}

	// Split off a tag from the (registry-stripped) name. A ':' after the last
	// '/' is a tag; a ':' inside a host was already handled above.
	tag := ""
	if colon := strings.LastIndex(name, ":"); colon >= 0 && !strings.Contains(name[colon+1:], "/") {
		tag = name[colon+1:]
		name = name[:colon]
	}

	if name == "" {
		return Reference{}, fmt.Errorf("reference %q has no repository", ref)
	}
	// Docker Hub bare names live under library/.
	if registry == DefaultRegistry && !strings.Contains(name, "/") {
		name = "library/" + name
	}
	if digest == "" && tag == "" {
		tag = DefaultTag
	}

	return Reference{Registry: registry, Repository: name, Tag: tag, Digest: digest}, nil
}

// looksLikeHost reports whether a leading path segment is a registry host rather
// than a repository namespace. This is the same heuristic Docker uses.
func looksLikeHost(s string) bool {
	return strings.ContainsAny(s, ".:") || s == "localhost"
}

// RefForPull returns the manifest reference to fetch: the digest if pinned
// (immutable, preferred), otherwise the tag.
func (r Reference) RefForPull() string {
	if r.Digest != "" {
		return r.Digest
	}
	return r.Tag
}

// String renders the reference back to canonical form.
func (r Reference) String() string {
	var b strings.Builder
	b.WriteString(r.Registry)
	b.WriteByte('/')
	b.WriteString(r.Repository)
	if r.Tag != "" {
		b.WriteByte(':')
		b.WriteString(r.Tag)
	}
	if r.Digest != "" {
		b.WriteByte('@')
		b.WriteString(r.Digest)
	}
	return b.String()
}

// validateDigest checks a "sha256:<64hex>" digest. Kept local (rather than
// importing sig) so the registry package has no dependency on the crypto layer.
func validateDigest(d string) error {
	alg, hexPart, ok := strings.Cut(d, ":")
	if !ok || alg != "sha256" || len(hexPart) != 64 {
		return fmt.Errorf("malformed digest %q: want sha256:<64 hex>", d)
	}
	for _, c := range hexPart {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return fmt.Errorf("malformed digest %q: non-hex", d)
		}
	}
	return nil
}
