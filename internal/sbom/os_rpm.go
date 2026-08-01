package sbom

import (
	"encoding/binary"
	"fmt"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// rpmDBPaths are the candidate rpm database locations across distributions and
// rpm versions (the sysimage path is the RHEL 9+/Fedora default).
var rpmDBPaths = []string{
	"var/lib/rpm/rpmdb.sqlite", // sqlite backend
	"var/lib/rpm/Packages.db",  // ndb backend
	"var/lib/rpm/Packages",     // Berkeley DB backend
	"usr/lib/sysimage/rpm/rpmdb.sqlite",
	"usr/lib/sysimage/rpm/Packages.db",
	"usr/lib/sysimage/rpm/Packages",
}

// rpmBackend extracts raw RPM header blobs from a database file's bytes.
type rpmBackend interface {
	// name identifies the backend for diagnostics.
	name() string
	// headers returns one header blob per installed package.
	headers(dbData []byte) ([][]byte, error)
}

// rpmCataloger enumerates RPM packages. The header parser (rpm_header.go) is
// complete and tested; the on-disk database backends (Berkeley DB / ndb /
// sqlite) are detected by magic and are a follow-up slice — until one lands,
// scanning an rpm-based image records a clear module error rather than silently
// dropping packages. Package identity/PURL logic here is exercised via an
// injected backend in tests.
type rpmCataloger struct {
	// backend, when non-nil, overrides magic-based detection (used in tests).
	backend rpmBackend
}

func (rpmCataloger) Name() string { return "rpm-db" }

func (c rpmCataloger) Catalog(tree *oci.FileTree, d Distro) ([]Component, []Relationship, error) {
	dbPath, dbData, ok := findRPMDB(tree)
	if !ok {
		return nil, nil, nil
	}
	backend := c.backend
	if backend == nil {
		b, err := detectRPMBackend(dbData)
		if err != nil {
			return nil, nil, fmt.Errorf("rpm db %q: %w", "/"+dbPath, err)
		}
		backend = b
	}
	blobs, err := backend.headers(dbData)
	if err != nil {
		return nil, nil, fmt.Errorf("rpm db %q (%s): %w", "/"+dbPath, backend.name(), err)
	}

	distroID := d.ID
	if distroID == "" {
		distroID = "redhat"
	}
	var comps []Component
	for _, blob := range blobs {
		pkg, err := parseRPMHeader(blob)
		if err != nil {
			continue
		}
		comp := Component{
			Type:    TypeOS,
			Name:    pkg.Name,
			Version: pkg.evr(),
			Source:  "/" + dbPath,
			FoundBy: c.Name(),
			PURL: purl("rpm", distroID, pkg.Name, pkg.evr(), map[string]string{
				"arch":   pkg.Arch,
				"distro": distroQualifier(distroID, d.VersionID),
				"epoch":  pkg.Epoch,
			}),
			CPEs: []string{cpe23(distroID, pkg.Name, pkg.evr())},
		}
		if pkg.License != "" {
			comp.Licenses = parseLicenseExpr(pkg.License)
		}
		comps = append(comps, comp)
	}
	return comps, nil, nil
}

// findRPMDB returns the first present rpm database path and its bytes.
func findRPMDB(tree *oci.FileTree) (string, []byte, bool) {
	for _, p := range rpmDBPaths {
		if f, ok := tree.Get(p); ok {
			return p, f.Data, true
		}
	}
	return "", nil, false
}

// detectRPMBackend identifies the rpm database format from its leading bytes and
// returns the matching decoder. All three on-disk backends (sqlite, ndb,
// Berkeley DB hash) are implemented; the shared rpm_header parser decodes the
// blobs each returns.
func detectRPMBackend(data []byte) (rpmBackend, error) {
	switch {
	case len(data) >= 16 && string(data[:15]) == "SQLite format 3":
		return rpmSQLiteBackend{}, nil
	case len(data) >= 4 && string(data[:4]) == "RpmP":
		return rpmNDBBackend{}, nil
	case isBDBHash(data):
		return rpmBDBBackend{}, nil
	default:
		return nil, fmt.Errorf("unrecognized rpm database format (not sqlite, ndb, or Berkeley DB hash)")
	}
}

// isBDBHash reports whether data is a Berkeley DB hash database by its metadata
// magic (offset 12), tolerating either byte order.
func isBDBHash(data []byte) bool {
	if len(data) < 16 {
		return false
	}
	return binary.LittleEndian.Uint32(data[12:16]) == bdbHashMagic ||
		binary.BigEndian.Uint32(data[12:16]) == bdbHashMagic
}
