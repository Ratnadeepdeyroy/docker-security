package compliance

import (
	"testing"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

var testNow = time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

// imageReport is a synthetic engine Report standing in for an image scan: it ran
// imageaudit/sbom/vuln/secrets (not dockerbench), the image runs as root
// (DS-RAT-IMG-001), and an SBOM + vuln summary were produced.
func imageReport() *engine.Report {
	return &engine.Report{
		Target:     "demo/app:latest",
		ModuleRuns: []engine.ModuleRun{{Module: "imageaudit"}, {Module: "sbom"}, {Module: "vuln"}, {Module: "secrets"}},
		Findings: []engine.Finding{
			{RuleID: "DS-RAT-IMG-001", Severity: engine.SeverityMedium, Title: "Image runs as root"},
			{RuleID: "DS-RAT-SBOM-001", Severity: engine.SeverityInfo, Title: "SBOM: 4 components"},
			{RuleID: "DS-RAT-VULN-000", Severity: engine.SeverityInfo, Title: "Vulnerability scan: 0 findings"},
		},
	}
}

func runFixture(t *testing.T, rep *engine.Report, reg *AttestationRegister) map[string]ControlResult {
	t.Helper()
	cat, err := LoadEmbeddedPacks()
	if err != nil {
		t.Fatal(err)
	}
	cr := RunPacks(cat, []string{"cis-docker", "nist-ssdf"}, rep, RunOptions{
		Now: testNow, ToolVersion: "test", Target: rep.Target, Register: reg,
	})
	out := map[string]ControlResult{}
	for _, r := range cr.Results {
		out[r.Framework+"/"+r.ID] = r
	}
	return out
}

func TestRunnerDispositions(t *testing.T) {
	got := runFixture(t, imageReport(), nil)

	cases := map[string]Disposition{
		"cis-docker/4.1":   DispFailed,        // DS-RAT-IMG-001 present (root)
		"cis-docker/4.6":   DispSatisfied,     // imageaudit ran, no DS-RAT-IMG-002
		"cis-docker/2.6":   DispNotApplicable, // dockerbench did not run
		"cis-docker/1.1.1": DispManual,        // manual control, no attestation
		"nist-ssdf/PS.3.2": DispSatisfied,     // DS-RAT-SBOM-001 present (present_means=pass)
		"nist-ssdf/RV.1.1": DispSatisfied,     // only INFO vuln summary → no violation
		"nist-ssdf/PW.4.1": DispSatisfied,     // secrets ran, no secret finding
		"nist-ssdf/PO.3.2": DispManual,        // hybrid, no automated pass signal
	}
	for key, want := range cases {
		if got[key].Disposition != want {
			t.Errorf("%s = %s, want %s (%s)", key, got[key].Disposition, want, got[key].Evidence.Observed)
		}
	}
}

func TestRunnerFlagsRealVulnerability(t *testing.T) {
	rep := imageReport()
	rep.Findings = append(rep.Findings, engine.Finding{RuleID: "DS-RAT-VULN-CVE-2021-23337", Severity: engine.SeverityHigh, Title: "lodash CVE"})
	got := runFixture(t, rep, nil)
	if got["nist-ssdf/RV.1.1"].Disposition != DispFailed {
		t.Errorf("RV.1.1 should FAIL with a real CVE present, got %s", got["nist-ssdf/RV.1.1"].Disposition)
	}
}

func TestWaiverAndAttestation(t *testing.T) {
	reg := &AttestationRegister{Entries: []RegisterEntry{
		{Kind: "waiver", Framework: "cis-docker", ControlID: "4.1", Owner: "sec", Justification: "base image", Expires: testNow.AddDate(1, 0, 0)},
		{Kind: "attestation", Framework: "cis-docker", ControlID: "1.1.1", Owner: "plat", Evidence: "runbook", Expires: testNow.AddDate(1, 0, 0)},
	}}
	got := runFixture(t, imageReport(), reg)
	if got["cis-docker/4.1"].Disposition != DispWaived {
		t.Errorf("4.1 should be Waived, got %s", got["cis-docker/4.1"].Disposition)
	}
	if got["cis-docker/1.1.1"].Disposition != DispSatisfied {
		t.Errorf("1.1.1 should be Satisfied via attestation, got %s", got["cis-docker/1.1.1"].Disposition)
	}
}

func TestExpiredEntriesDoNotCount(t *testing.T) {
	reg := &AttestationRegister{Entries: []RegisterEntry{
		{Kind: "waiver", Framework: "cis-docker", ControlID: "4.1", Owner: "sec", Expires: testNow.AddDate(-1, 0, 0)}, // expired
		{Kind: "attestation", Framework: "cis-docker", ControlID: "1.1.1", Owner: "plat", Expires: time.Time{}},       // no expiry → invalid
	}}
	got := runFixture(t, imageReport(), reg)
	if got["cis-docker/4.1"].Disposition != DispFailed {
		t.Errorf("expired waiver must not apply; 4.1 = %s, want Failed", got["cis-docker/4.1"].Disposition)
	}
	if got["cis-docker/1.1.1"].Disposition != DispManual {
		t.Errorf("no-expiry attestation must not count; 1.1.1 = %s, want Manual", got["cis-docker/1.1.1"].Disposition)
	}
}

func TestCoverageAndNoUnknown(t *testing.T) {
	cat, _ := LoadEmbeddedPacks()
	cr := RunPacks(cat, []string{"cis-docker", "nist-ssdf"}, imageReport(), RunOptions{Now: testNow, ToolVersion: "test", Target: "x"})
	for _, r := range cr.Results {
		if r.Disposition == DispUnknown {
			t.Errorf("control %s/%s is Unknown — the contract forbids it", r.Framework, r.ID)
		}
	}
	for _, s := range Coverage(cr) {
		if s.Total == 0 || s.CoveragePct < 0 || s.CoveragePct > 100 {
			t.Errorf("bad coverage stat: %+v", s)
		}
	}
}
