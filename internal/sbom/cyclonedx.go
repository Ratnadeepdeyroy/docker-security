package sbom

// CycloneDX 1.5 JSON structures (only the fields this tool emits).

type cdxBOM struct {
	BomFormat    string          `json:"bomFormat"`
	SpecVersion  string          `json:"specVersion"`
	SerialNumber string          `json:"serialNumber,omitempty"`
	Version      int             `json:"version"`
	Metadata     cdxMetadata     `json:"metadata"`
	Components   []cdxComponent  `json:"components"`
	Dependencies []cdxDependency `json:"dependencies,omitempty"`
}

type cdxMetadata struct {
	Timestamp string        `json:"timestamp,omitempty"`
	Tools     []cdxTool     `json:"tools"`
	Component *cdxComponent `json:"component,omitempty"`
}

type cdxTool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type cdxComponent struct {
	Type     string            `json:"type"`
	BOMRef   string            `json:"bom-ref,omitempty"`
	Name     string            `json:"name"`
	Version  string            `json:"version,omitempty"`
	PURL     string            `json:"purl,omitempty"`
	CPE      string            `json:"cpe,omitempty"`
	Licenses []cdxLicenseEntry `json:"licenses,omitempty"`
	Hashes   []cdxHash         `json:"hashes,omitempty"`
}

type cdxLicenseEntry struct {
	License *cdxLicense `json:"license,omitempty"`
}

type cdxLicense struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type cdxHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type cdxDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

func marshalCycloneDX(s *SBOM, meta DocMeta) ([]byte, error) {
	bom := cdxBOM{
		BomFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: meta.Serial,
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: meta.timestamp(),
			Tools:     []cdxTool{{Vendor: "docker-security", Name: meta.toolName(), Version: meta.ToolVersion}},
			Component: &cdxComponent{
				Type: cdxRootType(s.Source.Type),
				Name: s.Source.Name,
			},
		},
	}
	for _, c := range s.Components {
		cc := cdxComponent{
			Type:     cdxComponentType(c.Type),
			BOMRef:   c.Ref(),
			Name:     c.Name,
			Version:  c.Version,
			PURL:     c.PURL,
			Licenses: cdxLicenses(c.Licenses),
			Hashes:   cdxHashes(c.Hashes),
		}
		if len(c.CPEs) > 0 {
			cc.CPE = c.CPEs[0]
		}
		bom.Components = append(bom.Components, cc)
	}
	bom.Dependencies = cdxDependencies(s.Relationships)

	return encodeJSON(bom)
}

// cdxComponentType maps our component type onto the CycloneDX enum. Individual
// OS packages are libraries; the "operating-system" type is reserved for the
// distro component itself, which this tool does not emit as a package.
func cdxComponentType(t ComponentType) string {
	if t == TypeApp {
		return "application"
	}
	return "library"
}

func cdxRootType(sourceType string) string {
	if sourceType == "filesystem" {
		return "application"
	}
	return "container"
}

func cdxLicenses(ls []License) []cdxLicenseEntry {
	var out []cdxLicenseEntry
	for _, l := range ls {
		if l.ID != "" {
			out = append(out, cdxLicenseEntry{License: &cdxLicense{ID: l.ID}})
		} else if l.Name != "" {
			out = append(out, cdxLicenseEntry{License: &cdxLicense{Name: l.Name}})
		}
	}
	return out
}

func cdxHashes(hs []Hash) []cdxHash {
	var out []cdxHash
	for _, h := range hs {
		out = append(out, cdxHash{Alg: h.Algorithm, Content: h.Value})
	}
	return out
}

func cdxDependencies(rels []Relationship) []cdxDependency {
	byRef := map[string][]string{}
	var order []string
	for _, r := range rels {
		if r.From == "" || r.Type != "dependsOn" {
			continue
		}
		if _, seen := byRef[r.From]; !seen {
			order = append(order, r.From)
		}
		byRef[r.From] = append(byRef[r.From], r.To)
	}
	var out []cdxDependency
	for _, ref := range order {
		out = append(out, cdxDependency{Ref: ref, DependsOn: byRef[ref]})
	}
	return out
}
