package report

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

func TestSARIFIncludesProperties(t *testing.T) {
	r := &engine.Report{
		Tool:        "docker-security",
		TargetType:  engine.TargetImage,
		Target:      "fixture:latest",
		GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Findings: []engine.Finding{
			{
				RuleID:   "DS-RAT-SECRET-001",
				Module:   "secrets",
				Severity: engine.SeverityHigh,
				Title:    "hardcoded secret",
				Resource: "fixture:latest",
				Metadata: map[string]string{
					"confidence":  "high",
					"fingerprint": "abc123",
				},
			},
		},
	}

	var buf bytes.Buffer
	if err := (SARIF{}).Format(&buf, r); err != nil {
		t.Fatal(err)
	}

	var doc struct {
		Runs []struct {
			Results []struct {
				RuleID     string            `json:"ruleId"`
				Properties map[string]string `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	if len(doc.Runs) != 1 || len(doc.Runs[0].Results) != 1 {
		t.Fatalf("expected exactly one run with one result, got: %+v", doc)
	}

	props := doc.Runs[0].Results[0].Properties
	if props == nil {
		t.Fatal("result.properties is missing, expected metadata to be forwarded")
	}
	if got := props["confidence"]; got != "high" {
		t.Errorf("properties.confidence = %q, want %q", got, "high")
	}
	if got := props["fingerprint"]; got != "abc123" {
		t.Errorf("properties.fingerprint = %q, want %q", got, "abc123")
	}
}

func TestSARIFOmitsPropertiesWhenMetadataEmpty(t *testing.T) {
	r := &engine.Report{
		Tool:        "docker-security",
		TargetType:  engine.TargetImage,
		Target:      "fixture:latest",
		GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Findings: []engine.Finding{
			{RuleID: "DS-RAT-X-001", Module: "x", Severity: engine.SeverityHigh, Title: "boom", Resource: "fixture:latest"},
		},
	}

	var buf bytes.Buffer
	if err := (SARIF{}).Format(&buf, r); err != nil {
		t.Fatal(err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SARIF output is not valid JSON: %v", err)
	}

	runs := doc["runs"].([]any)
	results := runs[0].(map[string]any)["results"].([]any)
	result := results[0].(map[string]any)
	if _, ok := result["properties"]; ok {
		t.Errorf("expected no properties key when Metadata is empty, got: %+v", result)
	}
}
