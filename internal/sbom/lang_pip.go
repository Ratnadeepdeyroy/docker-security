package sbom

import (
	"path"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// pipCataloger enumerates Python packages from installed dist-info/egg-info
// metadata (the authoritative record of what is installed in the image).
type pipCataloger struct{}

func (pipCataloger) Name() string { return "python" }

func (c pipCataloger) Catalog(tree *oci.FileTree, _ Distro) ([]Component, []Relationship, error) {
	var comps []Component
	for _, f := range tree.Files() {
		base := path.Base(f.Path)
		dir := path.Base(path.Dir(f.Path))
		isDistInfo := base == "METADATA" && strings.HasSuffix(dir, ".dist-info")
		isEggInfo := base == "PKG-INFO" && strings.HasSuffix(dir, ".egg-info")
		if !isDistInfo && !isEggInfo {
			continue
		}
		if comp, ok := c.fromMetadata(f.Data, f.Path); ok {
			comps = append(comps, comp)
		}
	}
	return comps, nil, nil
}

func (c pipCataloger) fromMetadata(data []byte, srcPath string) (Component, bool) {
	fields := parseMailHeaders(string(data))
	name := fields["Name"]
	version := fields["Version"]
	if name == "" {
		return Component{}, false
	}
	comp := Component{
		Type:     TypeLibrary,
		Name:     name,
		Version:  version,
		Source:   "/" + srcPath,
		FoundBy:  c.Name(),
		Licenses: pythonLicenses(fields),
		PURL:     purl("pypi", "", normalizePyPIName(name), version, nil),
	}
	return comp, true
}

// normalizePyPIName applies PEP 503 normalization: lowercase and collapse runs
// of "-", "_", and "." into a single "-".
func normalizePyPIName(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	prevSep := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('-')
				prevSep = true
			}
			continue
		}
		b.WriteRune(r)
		prevSep = false
	}
	return strings.Trim(b.String(), "-")
}

// pythonLicenses extracts license info from the "License" field or, failing
// that, from a "License ::" trove classifier.
func pythonLicenses(fields map[string]string) []License {
	if lic := fields["License"]; lic != "" && lic != "UNKNOWN" {
		return parseLicenseExpr(lic)
	}
	if cls := fields["Classifier"]; cls != "" {
		for _, line := range strings.Split(cls, "\n") {
			if strings.HasPrefix(line, "License ::") {
				parts := strings.Split(line, "::")
				last := strings.TrimSpace(parts[len(parts)-1])
				if last != "" && last != "OSI Approved" {
					return []License{{Name: last}}
				}
			}
		}
	}
	return nil
}

// parseMailHeaders parses RFC822-style "Key: value" metadata (as used by
// PEP 566 core metadata), folding continuations and repeating multi-valued
// keys (e.g. Classifier) into newline-joined values.
func parseMailHeaders(content string) map[string]string {
	out := map[string]string{}
	lastKey := ""
	for _, line := range strings.Split(content, "\n") {
		if line == "" {
			break // headers end at the first blank line (body follows)
		}
		if (line[0] == ' ' || line[0] == '\t') && lastKey != "" {
			out[lastKey] += "\n" + strings.TrimSpace(line)
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		lastKey = k
		if existing, dup := out[k]; dup {
			out[k] = existing + "\n" + v
		} else {
			out[k] = v
		}
	}
	return out
}
