package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

func sampleReport() *engine.Report {
	return &engine.Report{
		Tool:        "docker-security",
		TargetType:  engine.TargetImage,
		Target:      "fixture:latest",
		GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Findings: []engine.Finding{
			{RuleID: "DS-RAT-X-001", Module: "x", Severity: engine.SeverityHigh, Title: "boom", Resource: "fixture:latest",
				Location: &engine.Location{Path: "Dockerfile", StartLine: 3, EndLine: 3}},
		},
	}
}

func TestGetKnownAndUnknownFormats(t *testing.T) {
	for _, name := range Formats() {
		if _, err := Get(name); err != nil {
			t.Errorf("Get(%q) errored: %v", name, err)
		}
	}
	if _, err := Get(""); err != nil {
		t.Errorf("empty format should default to table, got %v", err)
	}
	if _, err := Get("nonsense"); err == nil {
		t.Error("unknown format should error")
	}
}

func TestTableFormatterMentionsFinding(t *testing.T) {
	var buf bytes.Buffer
	if err := (Table{}).Format(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"DS-RAT-X-001", "HIGH", "boom"} {
		if !strings.Contains(out, want) {
			t.Errorf("table output missing %q:\n%s", want, out)
		}
	}
}

func TestJSONFormatterRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := (JSON{}).Format(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var back engine.Report
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("json output does not round-trip: %v", err)
	}
	if len(back.Findings) != 1 || back.Findings[0].Severity != engine.SeverityHigh {
		t.Errorf("round-tripped report lost data: %+v", back)
	}
}

func TestSARIFFormatterIsValidJSONWithSchema(t *testing.T) {
	var buf bytes.Buffer
	if err := (SARIF{}).Format(&buf, sampleReport()); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("SARIF version = %v, want 2.1.0", doc["version"])
	}
	if _, ok := doc["runs"]; !ok {
		t.Error("SARIF document missing runs[]")
	}
}
