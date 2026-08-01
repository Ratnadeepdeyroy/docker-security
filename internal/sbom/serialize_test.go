package sbom

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "regenerate golden SBOM files")

// fixtureSBOM is a small cross-ecosystem SBOM used for golden serialization.
func fixtureSBOM() *SBOM {
	return &SBOM{
		Source: Source{Type: "image", Name: "fixture:latest", ImageDigest: "sha256:deadbeef", Distro: "alpine 3.19.1"},
		Components: []Component{
			{
				Type: TypeOS, Name: "musl", Version: "1.2.4-r2",
				PURL:     "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=alpine-3.19.1",
				CPEs:     []string{"cpe:2.3:a:alpine:musl:1.2.4-r2:*:*:*:*:*:*:*"},
				Licenses: []License{{ID: "MIT"}},
				Hashes:   []Hash{{Algorithm: "SHA-1", Value: "000102030405060708090a0b0c0d0e0f10111213"}},
				FoundBy:  "apk-db", Source: "/lib/apk/db/installed",
			},
			{
				Type: TypeLibrary, Name: "left-pad", Version: "1.3.0",
				PURL:     "pkg:npm/left-pad@1.3.0",
				Licenses: []License{{Name: "WTFPL"}},
				FoundBy:  "npm",
			},
			{
				Type: TypeLibrary, Name: "requests", Version: "2.31.0",
				PURL:     "pkg:pypi/requests@2.31.0",
				Licenses: []License{{ID: "Apache-2.0"}},
				FoundBy:  "python",
			},
		},
	}
}

func fixtureMeta() DocMeta {
	return DocMeta{
		Timestamp:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Serial:      "urn:uuid:00000000-0000-4000-8000-000000000000",
		ToolName:    "dockersec",
		ToolVersion: "0.1.0-test",
	}
}

func TestGoldenSBOM(t *testing.T) {
	cases := []struct {
		name   string
		format Format
		golden string
	}{
		{"cyclonedx", FormatCycloneDX, "sbom.cdx.json"},
		{"spdx", FormatSPDX, "sbom.spdx.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Marshal(fixtureSBOM(), tc.format, fixtureMeta())
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			path := filepath.Join("testdata", tc.golden)
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if os.IsNotExist(err) {
				// First run: materialize the golden so the suite is green and
				// future runs compare against it.
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				want = got
			} else if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Errorf("%s output differs from golden %s (run: go test ./internal/sbom -update)", tc.name, path)
			}
		})
	}
}

func TestCycloneDXStructure(t *testing.T) {
	data, err := Marshal(fixtureSBOM(), FormatCycloneDX, fixtureMeta())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		Components  []struct {
			BOMRef string `json:"bom-ref"`
			PURL   string `json:"purl"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc.BomFormat != "CycloneDX" || doc.SpecVersion != "1.5" {
		t.Errorf("bomFormat/specVersion = %q/%q", doc.BomFormat, doc.SpecVersion)
	}
	if len(doc.Components) != 3 {
		t.Fatalf("expected 3 components, got %d", len(doc.Components))
	}
	for _, c := range doc.Components {
		if c.BOMRef == "" || c.PURL == "" {
			t.Errorf("component missing bom-ref or purl: %+v", c)
		}
	}
}

func TestSPDXStructure(t *testing.T) {
	data, err := Marshal(fixtureSBOM(), FormatSPDX, fixtureMeta())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		SPDXVersion string `json:"spdxVersion"`
		DataLicense string `json:"dataLicense"`
		Packages    []struct {
			SPDXID       string `json:"SPDXID"`
			ExternalRefs []struct {
				ReferenceType string `json:"referenceType"`
			} `json:"externalRefs"`
		} `json:"packages"`
		Relationships []struct {
			RelationshipType string `json:"relationshipType"`
		} `json:"relationships"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if doc.SPDXVersion != "SPDX-2.3" || doc.DataLicense != "CC0-1.0" {
		t.Errorf("spdxVersion/dataLicense = %q/%q", doc.SPDXVersion, doc.DataLicense)
	}
	if len(doc.Packages) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(doc.Packages))
	}
	describes := 0
	for _, r := range doc.Relationships {
		if r.RelationshipType == "DESCRIBES" {
			describes++
		}
	}
	if describes != 3 {
		t.Errorf("expected 3 DESCRIBES relationships, got %d", describes)
	}
	// Every package must carry a purl external ref.
	for _, p := range doc.Packages {
		found := false
		for _, ref := range p.ExternalRefs {
			if ref.ReferenceType == "purl" {
				found = true
			}
		}
		if !found {
			t.Errorf("package %s missing purl externalRef", p.SPDXID)
		}
	}
}

func TestDeterministicOutput(t *testing.T) {
	// Shuffled input must produce identical bytes after normalization.
	a, _ := Marshal(fixtureSBOM(), FormatCycloneDX, fixtureMeta())
	s := fixtureSBOM()
	s.Components[0], s.Components[2] = s.Components[2], s.Components[0]
	b, _ := Marshal(s, FormatCycloneDX, fixtureMeta())
	if string(a) != string(b) {
		t.Errorf("output not deterministic under input reordering")
	}
}
