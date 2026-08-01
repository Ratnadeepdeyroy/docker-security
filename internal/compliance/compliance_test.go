package compliance

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// sampleBenchmark is a tiny catalogue used across compliance tests. Note the
// control ids are intentionally out of numeric order and include "2.10" so the
// runner's numeric-aware sort is exercised.
func sampleBenchmark() Benchmark {
	return Benchmark{
		Code: "docker", Name: "CIS Docker Benchmark", Version: "1.6.0", Profile: "self-managed",
		Controls: []Control{
			{ID: "2.10", Title: "ten", Level: Level2, Scored: true, Remediation: "fix ten",
				Frameworks: []FrameworkRef{Ref(FrameworkNIST190, "4.5")}},
			{ID: "2.2", Title: "two", Level: Level1, Scored: true, Remediation: "fix two",
				Frameworks: []FrameworkRef{Ref(FrameworkNIST53, "AC-6")}},
			{ID: "2.1", Title: "one", Level: Level1, Scored: true, Remediation: "fix one",
				Frameworks: []FrameworkRef{Ref(FrameworkSTIG, "SRG-APP-000001")}},
		},
	}
}

// fixedAssessor returns a deterministic status per control id.
func fixedAssessor(m map[string]Status) Assessor {
	return func(c Control) Assessment {
		return Assessment{Status: m[c.ID], Evidence: "observed " + c.ID}
	}
}

func TestRunSortsNumerically(t *testing.T) {
	rep := sampleBenchmark().Run(fixedAssessor(map[string]Status{"2.1": StatusPass, "2.2": StatusFail, "2.10": StatusWarn}))
	var order []string
	for _, r := range rep.Results {
		order = append(order, r.Control.ID)
	}
	want := []string{"2.1", "2.2", "2.10"} // not lexicographic (2.10 last)
	if strings.Join(order, ",") != strings.Join(want, ",") {
		t.Errorf("order = %v, want %v", order, want)
	}
}

func TestRunTurnsUnknownIntoInfo(t *testing.T) {
	// An assessor that never sets a status ⇒ every control becomes INFO, not a
	// silent drop.
	rep := sampleBenchmark().Run(func(c Control) Assessment { return Assessment{} })
	for _, r := range rep.Results {
		if r.Status != StatusInfo {
			t.Errorf("control %s: got %s, want INFO for an unassessed control", r.Control.ID, r.Status)
		}
	}
}

func TestCountsAndScore(t *testing.T) {
	rep := sampleBenchmark().Run(fixedAssessor(map[string]Status{"2.1": StatusPass, "2.2": StatusFail, "2.10": StatusWarn}))
	c := rep.Counts()
	if c[StatusPass] != 1 || c[StatusFail] != 1 || c[StatusWarn] != 1 {
		t.Errorf("counts = %+v", c)
	}
	// Score is over PASS+FAIL only: 1 pass / 2 scorable = 50.
	if s := rep.Score(); s != 50 {
		t.Errorf("score = %d, want 50", s)
	}
}

func TestReferencesLeadWithCIS(t *testing.T) {
	c := Control{ID: "2.1", Frameworks: []FrameworkRef{Ref(FrameworkNIST190, "4.5.1"), Ref(FrameworkNIST53, "SC-7")}}
	refs := c.References("CIS Docker Benchmark")
	if refs[0] != "CIS Docker Benchmark 2.1" {
		t.Errorf("first reference = %q, want the CIS control", refs[0])
	}
	if len(refs) != 3 {
		t.Errorf("expected 3 references, got %v", refs)
	}
}

func TestLevelMarshalsAsProfileName(t *testing.T) {
	data, _ := json.Marshal(Level2)
	if string(data) != `"L2"` {
		t.Errorf("Level2 JSON = %s, want \"L2\"", data)
	}
}

func TestFindingsProjection(t *testing.T) {
	rep := sampleBenchmark().Run(fixedAssessor(map[string]Status{"2.1": StatusPass, "2.2": StatusFail, "2.10": StatusWarn}))
	fs := Findings("dockerbench", rep)

	byRule := map[string]engine.Finding{}
	for _, f := range fs {
		byRule[f.RuleID] = f
	}

	// Summary is always present.
	if _, ok := byRule["DS-RAT-CIS-SUMMARY"]; !ok {
		t.Fatalf("expected DS-RAT-CIS-SUMMARY finding; got rules %v", keys(byRule))
	}
	// PASS control (2.1) is NOT projected as a finding.
	if _, ok := byRule["DS-RAT-CIS-DOCKER-2.1"]; ok {
		t.Errorf("PASS control 2.1 should not become a finding")
	}
	// FAIL → High, with the DS-RAT-CIS- prefix and benchmark code.
	fail := byRule["DS-RAT-CIS-DOCKER-2.2"]
	if fail.Severity != engine.SeverityHigh {
		t.Errorf("FAIL severity = %s, want HIGH", fail.Severity)
	}
	if fail.Metadata["status"] != "FAIL" || fail.Remediation != "fix two" {
		t.Errorf("FAIL finding metadata/remediation wrong: %+v", fail)
	}
	// WARN → Medium.
	if warn := byRule["DS-RAT-CIS-DOCKER-2.10"]; warn.Severity != engine.SeverityMedium {
		t.Errorf("WARN severity = %s, want MEDIUM", warn.Severity)
	}
	// References must cite CIS + the mapped framework.
	if len(fail.References) < 2 {
		t.Errorf("FAIL finding should cite CIS + a framework, got %v", fail.References)
	}
}

func keys(m map[string]engine.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
