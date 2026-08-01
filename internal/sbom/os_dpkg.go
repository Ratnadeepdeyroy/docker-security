package sbom

import (
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// dpkgStatusPath is the Debian/Ubuntu package database.
const dpkgStatusPath = "var/lib/dpkg/status"

// dpkgCataloger enumerates Debian/Ubuntu (dpkg) packages from the status DB.
type dpkgCataloger struct{}

func (dpkgCataloger) Name() string { return "dpkg-db" }

func (c dpkgCataloger) Catalog(tree *oci.FileTree, d Distro) ([]Component, []Relationship, error) {
	f, ok := tree.Get(dpkgStatusPath)
	if !ok {
		return nil, nil, nil
	}
	distroID := d.ID
	if distroID == "" {
		distroID = "debian"
	}
	var comps []Component
	for _, para := range dpkgParagraphs(string(f.Data)) {
		name := para["Package"]
		if name == "" {
			continue
		}
		// Only report packages that are actually installed.
		if st := para["Status"]; st != "" && !strings.Contains(st, "installed") {
			continue
		}
		version := para["Version"]
		arch := para["Architecture"]
		comp := Component{
			Type:    TypeOS,
			Name:    name,
			Version: version,
			Source:  "/" + dpkgStatusPath,
			FoundBy: c.Name(),
			PURL: purl("deb", distroID, name, version, map[string]string{
				"arch":   arch,
				"distro": distroQualifier(distroID, d.VersionID),
			}),
			CPEs: []string{cpe23(distroID, name, version)},
		}
		comps = append(comps, comp)
	}
	return comps, nil, nil
}

// dpkgParagraphs parses the RFC822-style status file into records, folding
// continuation lines (leading space/tab) into the preceding field.
func dpkgParagraphs(content string) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	lastKey := ""
	flush := func() {
		if len(cur) > 0 {
			out = append(out, cur)
			cur = map[string]string{}
			lastKey = ""
		}
	}
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && lastKey != "" {
			cur[lastKey] += "\n" + strings.TrimSpace(line)
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		lastKey = strings.TrimSpace(k)
		cur[lastKey] = strings.TrimSpace(v)
	}
	flush()
	return out
}
