package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunSuiteAgainstBaseline(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "baseline.policytest.json"))
	if err != nil {
		t.Fatalf("read suite: %v", err)
	}
	suite, err := ParseSuite(data)
	if err != nil {
		t.Fatalf("parse suite: %v", err)
	}
	eng := loadPolicy(t, suite.Policy)

	sr := eng.RunSuite(suite.Cases, fixedNow)
	if !sr.OK() {
		for _, r := range sr.Results {
			if !r.Pass {
				t.Errorf("case %q failed: %s", r.Name, r.Detail)
			}
		}
		t.Fatalf("suite failed: %d/%d passed", sr.Passed, sr.Passed+sr.Failed)
	}
	if sr.Passed != len(suite.Cases) {
		t.Fatalf("passed %d, want %d", sr.Passed, len(suite.Cases))
	}
}

// TestSuiteCatchesRegression flips an expectation and confirms the harness
// reports the failure — proving the harness actually asserts, not just runs.
func TestSuiteCatchesRegression(t *testing.T) {
	eng := loadPolicy(t, "baseline.policy.json")
	bad := []Case{{
		Name:   "wrongly expects allow for an unsigned critical image",
		Input:  CaseInput{Attest: StaticAttestation{IsSigned: false}, Findings: []FindingJSON{{RuleID: "x", Module: "vuln", Severity: "CRITICAL", Title: "c"}}},
		Expect: DecisionAllow,
	}}
	sr := eng.RunSuite(bad, fixedNow)
	if sr.OK() {
		t.Fatal("expected the harness to catch the wrong expectation")
	}
}
