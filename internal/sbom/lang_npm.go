package sbom

import (
	"encoding/json"
	"path"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// npmCataloger enumerates Node packages from installed node_modules manifests
// and from package-lock.json lockfiles.
type npmCataloger struct{}

func (npmCataloger) Name() string { return "npm" }

func (c npmCataloger) Catalog(tree *oci.FileTree, _ Distro) ([]Component, []Relationship, error) {
	var comps []Component
	for _, f := range tree.Files() {
		switch {
		case isNodeModulesManifest(f.Path):
			if comp, ok := c.fromPackageJSON(f.Data, f.Path); ok {
				comps = append(comps, comp)
			}
		case path.Base(f.Path) == "package-lock.json":
			comps = append(comps, c.fromLock(f.Data, f.Path)...)
		}
	}
	return comps, nil, nil
}

// isNodeModulesManifest matches a package.json that is an installed dependency
// (directly under a node_modules/<pkg> or node_modules/@scope/<pkg> directory).
func isNodeModulesManifest(p string) bool {
	if path.Base(p) != "package.json" {
		return false
	}
	dir := path.Dir(p) // node_modules/foo  OR  node_modules/@scope/foo
	parent := path.Base(path.Dir(dir))
	if parent == "node_modules" {
		return true
	}
	// Scoped package: parent is "@scope", grandparent is "node_modules".
	return strings.HasPrefix(parent, "@") && path.Base(path.Dir(path.Dir(dir))) == "node_modules"
}

type npmPackageJSON struct {
	Name    string          `json:"name"`
	Version string          `json:"version"`
	License json.RawMessage `json:"license"`
}

func (c npmCataloger) fromPackageJSON(data []byte, srcPath string) (Component, bool) {
	var pj npmPackageJSON
	if err := json.Unmarshal(data, &pj); err != nil || pj.Name == "" {
		return Component{}, false
	}
	return c.component(pj.Name, pj.Version, npmLicenses(pj.License), "/"+srcPath), true
}

type npmLock struct {
	// v2/v3
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
	// v1
	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"`
}

func (c npmCataloger) fromLock(data []byte, srcPath string) []Component {
	var lock npmLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil
	}
	var out []Component
	if len(lock.Packages) > 0 {
		for p, v := range lock.Packages {
			name := lockPkgName(p)
			if name == "" || v.Version == "" {
				continue // skip the root package (empty key)
			}
			out = append(out, c.component(name, v.Version, nil, "/"+srcPath))
		}
		return out
	}
	for name, v := range lock.Dependencies {
		if name == "" {
			continue
		}
		out = append(out, c.component(name, v.Version, nil, "/"+srcPath))
	}
	return out
}

// lockPkgName extracts the package name from a v2/v3 lockfile key such as
// "node_modules/@scope/foo" or "node_modules/foo".
func lockPkgName(key string) string {
	i := strings.LastIndex(key, "node_modules/")
	if i < 0 {
		return ""
	}
	return key[i+len("node_modules/"):]
}

func (c npmCataloger) component(fullName, version string, lics []License, src string) Component {
	ns, name := splitNpmName(fullName)
	return Component{
		Type:     TypeLibrary,
		Name:     fullName,
		Version:  version,
		Source:   src,
		FoundBy:  c.Name(),
		Licenses: lics,
		PURL:     purl("npm", ns, name, version, nil),
	}
}

// splitNpmName splits a possibly-scoped npm name into (namespace, name). For
// "@scope/pkg" it returns ("@scope", "pkg"); for "pkg" it returns ("", "pkg").
func splitNpmName(full string) (string, string) {
	if strings.HasPrefix(full, "@") {
		if i := strings.Index(full, "/"); i > 0 {
			return full[:i], full[i+1:]
		}
	}
	return "", full
}

// npmLicenses parses the polymorphic package.json "license" field, which may be
// a string ("MIT") or, in older packages, an object ({"type":"MIT"}).
func npmLicenses(raw json.RawMessage) []License {
	if len(raw) == 0 {
		return nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return parseLicenseExpr(s)
	}
	var obj struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil && obj.Type != "" {
		return parseLicenseExpr(obj.Type)
	}
	return nil
}
