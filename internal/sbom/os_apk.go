package sbom

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// apkPath is the Alpine package database.
const apkPath = "lib/apk/db/installed"

// apkCataloger enumerates Alpine (apk) packages from /lib/apk/db/installed.
type apkCataloger struct{}

func (apkCataloger) Name() string { return "apk-db" }

func (c apkCataloger) Catalog(tree *oci.FileTree, d Distro) ([]Component, []Relationship, error) {
	f, ok := tree.Get(apkPath)
	if !ok {
		return nil, nil, nil
	}
	distroID := d.ID
	if distroID == "" {
		distroID = "alpine"
	}
	var comps []Component
	for _, rec := range apkRecords(string(f.Data)) {
		name := rec["P"]
		version := rec["V"]
		if name == "" {
			continue
		}
		comp := Component{
			Type:    TypeOS,
			Name:    name,
			Version: version,
			Source:  "/" + apkPath,
			FoundBy: c.Name(),
			PURL: purl("apk", distroID, name, version, map[string]string{
				"arch":   rec["A"],
				"distro": distroQualifier(distroID, d.VersionID),
			}),
		}
		if arch := rec["A"]; arch != "" {
			comp.CPEs = []string{cpe23(distroID, name, version)}
		}
		if lic := rec["L"]; lic != "" {
			comp.Licenses = parseLicenseExpr(lic)
		}
		if h := apkChecksum(rec["C"]); (h != Hash{}) {
			comp.Hashes = []Hash{h}
		}
		comps = append(comps, comp)
	}
	return comps, nil, nil
}

// apkRecords splits the installed DB into records (blank-line separated) of
// single-line "K:value" fields.
func apkRecords(content string) []map[string]string {
	var out []map[string]string
	cur := map[string]string{}
	flush := func() {
		if len(cur) > 0 {
			out = append(out, cur)
			cur = map[string]string{}
		}
	}
	for _, line := range strings.Split(content, "\n") {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		cur[k] = v
	}
	flush()
	return out
}

// apkChecksum decodes an apk "C:" field. A "Q1" prefix denotes a base64-encoded
// SHA-1 digest.
func apkChecksum(s string) Hash {
	if strings.HasPrefix(s, "Q1") {
		raw, err := base64.StdEncoding.DecodeString(s[2:])
		if err == nil && len(raw) == 20 {
			return Hash{Algorithm: "SHA-1", Value: hex.EncodeToString(raw)}
		}
	}
	return Hash{}
}
