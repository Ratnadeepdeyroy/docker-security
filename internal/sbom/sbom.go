// Package sbom builds a Software Bill of Materials from a container image or a
// filesystem: it loads the image (via internal/oci), walks the flattened file
// tree with a set of catalogers (OS package DBs and language manifests), and
// serializes the result to SPDX 2.3 and CycloneDX 1.5. The same in-memory SBOM
// is exposed via Generate so later phases (vulnerability matching) can reuse it
// without rescanning. Output is deterministic: components and relationships are
// sorted, and the only time-varying fields (document timestamp, serial number)
// are injected by the caller.
package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"sort"
	"strings"
)

// ComponentType classifies a component for reporting and serialization.
type ComponentType string

const (
	TypeOS      ComponentType = "operating-system"
	TypeLibrary ComponentType = "library"
	TypeApp     ComponentType = "application"
)

// License is a detected license for a component.
type License struct {
	// ID is an SPDX license identifier (e.g. "MIT", "GPL-2.0-only") when the
	// value maps to one; otherwise Name carries the free-text value.
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// Hash is a content digest recorded for a component.
type Hash struct {
	Algorithm string `json:"algorithm"` // e.g. "SHA-256", "SHA-1", "MD5"
	Value     string `json:"value"`
}

// Component is a single package or dependency discovered in the scanned artifact.
type Component struct {
	Type     ComponentType `json:"type"`
	Name     string        `json:"name"`
	Version  string        `json:"version"`
	PURL     string        `json:"purl,omitempty"`
	CPEs     []string      `json:"cpes,omitempty"`
	Licenses []License     `json:"licenses,omitempty"`
	Hashes   []Hash        `json:"hashes,omitempty"`
	// Source is the file path the component was cataloged from.
	Source string `json:"source,omitempty"`
	// FoundBy is the cataloger name that produced the component.
	FoundBy string `json:"found_by,omitempty"`
}

// key is the stable identity of a component, used for dedup and reference ids.
func (c Component) key() string {
	if c.PURL != "" {
		return c.PURL
	}
	return string(c.Type) + "|" + c.Name + "@" + c.Version
}

// Ref returns a deterministic, unique-enough identifier for the component,
// suitable as an SPDXID suffix or CycloneDX bom-ref.
func (c Component) Ref() string {
	sum := sha256.Sum256([]byte(c.key()))
	name := sanitizeRef(c.Name)
	if name == "" {
		name = "component"
	}
	return name + "-" + hex.EncodeToString(sum[:])[:12]
}

// Relationship links two components (or a component to the document root).
type Relationship struct {
	From string `json:"from"` // component Ref, or "" for the document/root
	To   string `json:"to"`   // component Ref
	Type string `json:"type"` // e.g. "contains", "dependsOn"
}

// Source describes what was scanned to produce the SBOM.
type Source struct {
	Type        string `json:"type"` // "image" | "filesystem"
	Name        string `json:"name"` // image ref or path
	ImageDigest string `json:"image_digest,omitempty"`
	Distro      string `json:"distro,omitempty"` // e.g. "alpine 3.19"
}

// SBOM is the assembled bill of materials.
type SBOM struct {
	Source        Source         `json:"source"`
	Components    []Component    `json:"components"`
	Relationships []Relationship `json:"relationships,omitempty"`
	// Warnings records non-fatal cataloger problems (e.g. an rpm database in a
	// backend format not yet decodable) so callers can surface them without the
	// whole SBOM failing.
	Warnings []string `json:"warnings,omitempty"`
}

// DistroNameVersion splits Source.Distro (e.g. "alpine 3.19.1") into its
// distro id and version. Both are empty when no distro was detected.
func (s *SBOM) DistroNameVersion() (string, string) {
	if s.Source.Distro == "" {
		return "", ""
	}
	if i := strings.IndexByte(s.Source.Distro, ' '); i >= 0 {
		return s.Source.Distro[:i], s.Source.Distro[i+1:]
	}
	return s.Source.Distro, ""
}

// normalize deduplicates components by identity and sorts components and
// relationships into a stable order, making the SBOM byte-reproducible.
func (s *SBOM) normalize() {
	seen := map[string]int{}
	var deduped []Component
	for _, c := range s.Components {
		if idx, ok := seen[c.key()]; ok {
			deduped[idx] = mergeComponents(deduped[idx], c)
			continue
		}
		seen[c.key()] = len(deduped)
		deduped = append(deduped, c)
	}
	deduped = dropRedundantBinaryHits(deduped)
	for i := range deduped {
		sortLicenses(deduped[i].Licenses)
		sort.Strings(deduped[i].CPEs)
		sortHashes(deduped[i].Hashes)
	}
	sort.SliceStable(deduped, func(i, j int) bool {
		if deduped[i].Type != deduped[j].Type {
			return deduped[i].Type < deduped[j].Type
		}
		if deduped[i].Name != deduped[j].Name {
			return deduped[i].Name < deduped[j].Name
		}
		if deduped[i].Version != deduped[j].Version {
			return deduped[i].Version < deduped[j].Version
		}
		return deduped[i].PURL < deduped[j].PURL
	})
	s.Components = deduped

	sort.SliceStable(s.Relationships, func(i, j int) bool {
		a, b := s.Relationships[i], s.Relationships[j]
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		return a.Type < b.Type
	})
}

// mergeComponents folds a duplicate's extra metadata into the kept component.
func mergeComponents(keep, dup Component) Component {
	keep.Licenses = append(keep.Licenses, dup.Licenses...)
	keep.Licenses = dedupLicenses(keep.Licenses)
	keep.CPEs = dedupStrings(append(keep.CPEs, dup.CPEs...))
	keep.Hashes = dedupHashes(append(keep.Hashes, dup.Hashes...))
	if keep.PURL == "" {
		keep.PURL = dup.PURL
	}
	return keep
}

// dropRedundantBinaryHits removes components produced by the binary
// classifier cataloger (binclass.go) when a component with the same name and
// version is already present from another source, such as an OS package
// database. The classifier is a fallback for runtimes a package manager
// never registered (e.g. a hand-copied interpreter binary); it must not
// contribute a second, redundant component once a package-DB cataloger has
// already identified the same name@version.
//
// A verbatim Name+"@"+Version comparison never fires against real distro
// output: OS-package catalogers use the distro's own package name (e.g.
// Alpine/Debian's "python3", not the binary classifier's canonical
// "python") and the distro's revisioned version string (e.g. "3.11.6-r0" or
// "3.11.2-1+deb12u1", not the bare upstream "3.11.6"). crossEcosystemKey
// normalizes both sides so the comparison actually matches in that case,
// while still comparing exactly (and thus keeping the binary hit) when no
// OS package claims the same runtime at all.
func dropRedundantBinaryHits(comps []Component) []Component {
	claimed := map[string]bool{}
	for _, c := range comps {
		if c.FoundBy == binaryClassifierName {
			continue
		}
		claimed[crossEcosystemKey(c.Name, c.Version)] = true
	}
	out := make([]Component, 0, len(comps))
	for _, c := range comps {
		if c.FoundBy == binaryClassifierName && claimed[crossEcosystemKey(c.Name, c.Version)] {
			continue
		}
		out = append(out, c)
	}
	return out
}

// crossEcosystemKey builds the comparison key dropRedundantBinaryHits uses to
// recognize that a binary-classifier hit and an OS-package hit describe the
// same installed runtime, despite the two ecosystems' different naming and
// versioning conventions.
func crossEcosystemKey(name, version string) string {
	return normalizeRuntimeName(name) + "@" + normalizeRuntimeVersion(version)
}

// runtimeNameSuffixRe strips a version-like suffix directly appended to a
// name with no separator, e.g. Alpine/Debian's package name "python3" or
// "python3.11" versus the binary classifier's canonical "python".
var runtimeNameSuffixRe = regexp.MustCompile(`^([A-Za-z][A-Za-z+-]*?)[0-9][0-9.]*$`)

// normalizeRuntimeName strips a bare trailing version suffix from name (and
// lowercases it) so a distro package name like "python3" or "python3.11"
// compares equal to the binary classifier's canonical name "python".
func normalizeRuntimeName(name string) string {
	lower := strings.ToLower(name)
	if m := runtimeNameSuffixRe.FindStringSubmatch(lower); m != nil {
		return m[1]
	}
	return lower
}

// runtimeVersionPrefixRe matches a version string's leading dotted-numeric
// run, e.g. "3.11.6" out of "3.11.6-r0" or "3.11.2" out of
// "3.11.2-1+deb12u1".
var runtimeVersionPrefixRe = regexp.MustCompile(`^\d+(?:\.\d+)*`)

// normalizeRuntimeVersion strips a distro packaging revision suffix (Alpine's
// "-rN", Debian's "-N" or "-N+debNNuN", a "~..." backport marker, etc.) from
// version, leaving just the upstream dotted-numeric version the binary
// classifier reports.
func normalizeRuntimeVersion(version string) string {
	return runtimeVersionPrefixRe.FindString(version)
}

func sanitizeRef(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func sortLicenses(ls []License) {
	sort.SliceStable(ls, func(i, j int) bool {
		if ls[i].ID != ls[j].ID {
			return ls[i].ID < ls[j].ID
		}
		return ls[i].Name < ls[j].Name
	})
}

func sortHashes(hs []Hash) {
	sort.SliceStable(hs, func(i, j int) bool {
		if hs[i].Algorithm != hs[j].Algorithm {
			return hs[i].Algorithm < hs[j].Algorithm
		}
		return hs[i].Value < hs[j].Value
	})
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func dedupLicenses(in []License) []License {
	seen := map[License]bool{}
	var out []License
	for _, l := range in {
		if (l == License{}) || seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out
}

func dedupHashes(in []Hash) []Hash {
	seen := map[Hash]bool{}
	var out []Hash
	for _, h := range in {
		if (h == Hash{}) || seen[h] {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}
