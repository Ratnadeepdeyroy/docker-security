package mcp

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// update regenerates golden files: go test ./internal/mcp -update.
var update = flag.Bool("update", false, "regenerate golden files")

// TestGoldenExplain pins the deterministic explanation output for a
// representative finding, so a regression in categorization, step-splitting, or
// framework extraction is caught byte-for-byte.
func TestGoldenExplain(t *testing.T) {
	f := engine.Finding{
		RuleID:      "DS-RAT-VULN-042",
		Module:      "vuln",
		Severity:    engine.SeverityCritical,
		Title:       "openssl 3.0.1 affected by CVE-2022-3602",
		Description: "The installed openssl is within the affected range of a published advisory.",
		Resource:    "pkg:deb/debian/openssl@3.0.1",
		Remediation: "Upgrade openssl to 3.0.7 or later; rebuild and redeploy the image",
		References:  []string{"https://attack.mitre.org/techniques/T1190/", "https://nvd.nist.gov/vuln/detail/CVE-2022-3602"},
		Metadata:    map[string]string{"cwe": "CWE-787", "cvss": "9.8"},
		Location:    &engine.Location{Path: "var/lib/dpkg/status", StartLine: 12},
	}
	got, err := json.MarshalIndent(Explain(f), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	golden := filepath.Join("testdata", "explain_vuln.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run -update to create): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("explanation drifted from golden:\n got:\n%s\nwant:\n%s", got, want)
	}
}
