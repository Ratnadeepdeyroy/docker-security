package sbom

import "strings"

// SPDX 2.3 JSON structures (only the fields this tool emits).

type spdxDoc struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo,omitempty"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	ExternalRefs     []spdxExternalRef `json:"externalRefs,omitempty"`
	Checksums        []spdxChecksum    `json:"checksums,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

const spdxNoAssertion = "NOASSERTION"

func marshalSPDX(s *SBOM, meta DocMeta) ([]byte, error) {
	name := s.Source.Name
	if name == "" {
		name = "sbom"
	}
	doc := spdxDoc{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              name,
		DocumentNamespace: "https://docker-security/spdx/" + sanitizeRef(name) + "-" + strings.TrimPrefix(meta.Serial, "urn:uuid:"),
		CreationInfo: spdxCreationInfo{
			Created:  meta.timestamp(),
			Creators: []string{"Tool: " + meta.toolName() + "-" + meta.ToolVersion, "Organization: docker-security"},
		},
	}

	// DOCUMENT DESCRIBES every top-level package.
	for _, c := range s.Components {
		id := "SPDXRef-Package-" + c.Ref()
		pkg := spdxPackage{
			SPDXID:           id,
			Name:             c.Name,
			VersionInfo:      c.Version,
			DownloadLocation: spdxNoAssertion,
			FilesAnalyzed:    false,
			LicenseConcluded: spdxNoAssertion,
			LicenseDeclared:  spdxLicense(c.Licenses),
			CopyrightText:    spdxNoAssertion,
		}
		if c.PURL != "" {
			pkg.ExternalRefs = append(pkg.ExternalRefs, spdxExternalRef{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  c.PURL,
			})
		}
		for _, cpe := range c.CPEs {
			pkg.ExternalRefs = append(pkg.ExternalRefs, spdxExternalRef{
				ReferenceCategory: "SECURITY",
				ReferenceType:     "cpe23Type",
				ReferenceLocator:  cpe,
			})
		}
		for _, h := range c.Hashes {
			pkg.Checksums = append(pkg.Checksums, spdxChecksum{
				Algorithm:     spdxChecksumAlgo(h.Algorithm),
				ChecksumValue: h.Value,
			})
		}
		doc.Packages = append(doc.Packages, pkg)
		doc.Relationships = append(doc.Relationships, spdxRelationship{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelatedSPDXElement: id,
			RelationshipType:   "DESCRIBES",
		})
	}

	// Component-to-component relationships from catalogers.
	for _, r := range s.Relationships {
		if r.From == "" || r.To == "" {
			continue
		}
		doc.Relationships = append(doc.Relationships, spdxRelationship{
			SPDXElementID:      "SPDXRef-Package-" + r.From,
			RelatedSPDXElement: "SPDXRef-Package-" + r.To,
			RelationshipType:   spdxRelType(r.Type),
		})
	}

	return encodeJSON(doc)
}

// spdxLicense renders declared license from clean SPDX identifiers, joining
// multiple with AND. Free-text (non-identifier) licenses yield NOASSERTION
// rather than emitting an invalid license expression.
func spdxLicense(ls []License) string {
	var ids []string
	for _, l := range ls {
		if l.ID != "" {
			ids = append(ids, l.ID)
		}
	}
	if len(ids) == 0 {
		return spdxNoAssertion
	}
	if len(ids) == 1 {
		return ids[0]
	}
	return "(" + strings.Join(ids, " AND ") + ")"
}

func spdxChecksumAlgo(a string) string {
	return strings.ReplaceAll(strings.ToUpper(a), "-", "")
}

func spdxRelType(t string) string {
	switch t {
	case "dependsOn":
		return "DEPENDS_ON"
	case "contains":
		return "CONTAINS"
	default:
		return "OTHER"
	}
}
