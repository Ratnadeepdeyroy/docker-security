package sbom

import (
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// Cataloger discovers components of one ecosystem within a file tree. Each
// cataloger is self-contained: it decides which files it cares about, parses
// them, and returns components plus any intra-ecosystem relationships it can
// determine (e.g. a lockfile dependency graph).
type Cataloger interface {
	// Name is the stable identifier recorded as Component.FoundBy.
	Name() string
	// Catalog walks the tree and returns discovered components. Distro carries
	// OS identity for building OS-package PURLs.
	Catalog(tree *oci.FileTree, d Distro) ([]Component, []Relationship, error)
}

// DefaultCatalogers returns the built-in catalogers in a stable order.
func DefaultCatalogers() []Cataloger {
	return []Cataloger{
		apkCataloger{},
		dpkgCataloger{},
		rpmCataloger{},
		npmCataloger{},
		pipCataloger{},
		golangCataloger{},
		binClassifierCataloger{},
	}
}

// Distro identifies the operating system of the scanned image.
type Distro struct {
	ID        string // os-release ID, e.g. "alpine", "debian", "ubuntu", "rhel"
	VersionID string // os-release VERSION_ID, e.g. "3.19.1", "11"
	Name      string // pretty name, e.g. "Alpine Linux v3.19"
}

func (d Distro) String() string {
	switch {
	case d.ID == "":
		return ""
	case d.VersionID == "":
		return d.ID
	default:
		return d.ID + " " + d.VersionID
	}
}

// detectDistro reads /etc/os-release (falling back to /etc/alpine-release) to
// identify the image's operating system.
func detectDistro(tree *oci.FileTree) Distro {
	var d Distro
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		if f, ok := tree.Get(p); ok {
			kv := parseOSRelease(string(f.Data))
			d.ID = kv["ID"]
			d.VersionID = kv["VERSION_ID"]
			d.Name = kv["PRETTY_NAME"]
			break
		}
	}
	if d.ID == "" {
		if f, ok := tree.Get("etc/alpine-release"); ok {
			d.ID = "alpine"
			d.VersionID = strings.TrimSpace(string(f.Data))
			d.Name = "Alpine Linux v" + d.VersionID
		}
	}
	return d
}

// parseOSRelease parses the shell-style KEY=VALUE os-release format, stripping
// surrounding quotes from values.
func parseOSRelease(content string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[strings.TrimSpace(k)] = v
	}
	return out
}
