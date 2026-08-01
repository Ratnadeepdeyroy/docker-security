package compliance

import (
	"encoding/json"
	"strings"
	"testing"
)

func sampleComplianceReport(t *testing.T) *ComplianceReport {
	t.Helper()
	cat, err := LoadEmbeddedPacks()
	if err != nil {
		t.Fatal(err)
	}
	return RunPacks(cat, []string{"cis-docker", "nist-ssdf"}, imageReport(), RunOptions{
		Now: testNow, ToolVersion: "test", Target: "demo/app:latest",
	})
}

func TestRenderAllFormats(t *testing.T) {
	rep := sampleComplianceReport(t)
	for _, f := range ExportFormats() {
		data, err := Render(rep, f)
		if err != nil {
			t.Fatalf("Render(%s): %v", f, err)
		}
		if len(data) == 0 {
			t.Errorf("Render(%s) produced no output", f)
		}
	}
	if _, err := Render(rep, "nonsense"); err == nil {
		t.Error("unknown format should error")
	}
}

func TestOSCALIsValidJSON(t *testing.T) {
	data, err := Render(sampleComplianceReport(t), ExportOSCAL)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		AR struct {
			Metadata struct {
				OSCALVersion string `json:"oscal-version"`
			} `json:"metadata"`
			Results []struct {
				Findings []struct {
					Target struct {
						Status struct {
							State string `json:"state"`
						} `json:"status"`
					} `json:"target"`
				} `json:"findings"`
			} `json:"results"`
		} `json:"assessment-results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("OSCAL not valid JSON: %v", err)
	}
	if doc.AR.Metadata.OSCALVersion != "1.1.2" {
		t.Errorf("oscal-version = %q", doc.AR.Metadata.OSCALVersion)
	}
	if len(doc.AR.Results) != 1 || len(doc.AR.Results[0].Findings) == 0 {
		t.Fatal("OSCAL has no findings")
	}
	for _, f := range doc.AR.Results[0].Findings {
		if s := f.Target.Status.State; s != "satisfied" && s != "not-satisfied" {
			t.Errorf("invalid OSCAL state %q", s)
		}
	}
}

func TestCSVHasCrosswalkColumn(t *testing.T) {
	data, err := Render(sampleComplianceReport(t), ExportCSV)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if !strings.Contains(lines[0], "maps_to") {
		t.Errorf("CSV header missing maps_to column: %q", lines[0])
	}
	if len(lines) != 1+len(sampleComplianceReport(t).Results) {
		t.Errorf("CSV row count = %d, want header + %d controls", len(lines), len(sampleComplianceReport(t).Results))
	}
}

func TestRenderIsDeterministic(t *testing.T) {
	a, _ := Render(sampleComplianceReport(t), ExportJSON)
	b, _ := Render(sampleComplianceReport(t), ExportJSON)
	if string(a) != string(b) {
		t.Error("compliance JSON render is not deterministic")
	}
}
