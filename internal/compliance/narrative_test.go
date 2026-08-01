package compliance

import (
	"strings"
	"testing"
	"time"
)

func TestNarrativeIsDeterministic(t *testing.T) {
	rep := sampleBenchmark().Run(fixedAssessor(map[string]Status{"2.1": StatusPass, "2.2": StatusFail, "2.10": StatusFail}))
	now := time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC)

	first := BuildNarrative(rep, NarrativeOptions{Now: now}).Text()
	for i := 0; i < 5; i++ {
		again := BuildNarrative(rep, NarrativeOptions{Now: now}).Text()
		if again != first {
			t.Fatalf("narrative text is non-deterministic")
		}
	}
	if !strings.Contains(first, "compliance score") {
		t.Errorf("narrative should state a score; got:\n%s", first)
	}
	if !strings.Contains(first, "as of 2026-07-04T12:00:00Z") {
		t.Errorf("narrative should use the injected clock; got:\n%s", first)
	}
}

func TestNarrativeTopFailuresRankLevel1First(t *testing.T) {
	b := Benchmark{
		Code: "docker", Name: "CIS Docker Benchmark", Version: "1.6.0",
		Controls: []Control{
			{ID: "9.9", Title: "L2 fail", Level: Level2, Scored: true, Remediation: "fix l2"},
			{ID: "1.1", Title: "L1 fail", Level: Level1, Scored: true, Remediation: "fix l1"},
		},
	}
	rep := b.Run(fixedAssessor(map[string]Status{"9.9": StatusFail, "1.1": StatusFail}))
	n := BuildNarrative(rep, NarrativeOptions{Now: time.Unix(0, 0).UTC()})
	if len(n.TopFailures) != 2 {
		t.Fatalf("expected 2 top failures, got %d", len(n.TopFailures))
	}
	if n.TopFailures[0].ControlID != "1.1" {
		t.Errorf("Level 1 failure should rank first, got %s", n.TopFailures[0].ControlID)
	}
}

func TestNarrativeIncludesDriftAndCoverage(t *testing.T) {
	baseline := sampleBenchmark().Run(fixedAssessor(map[string]Status{"2.1": StatusPass, "2.2": StatusPass, "2.10": StatusPass}))
	cur := sampleBenchmark().Run(fixedAssessor(map[string]Status{"2.1": StatusFail, "2.2": StatusPass, "2.10": StatusPass}))
	n := BuildNarrative(cur, NarrativeOptions{Now: time.Unix(0, 0).UTC(), Baseline: baseline})

	if n.Drift == nil || len(n.Drift.Regressed) != 1 {
		t.Fatalf("narrative should carry the since-last-run drift")
	}
	// Framework coverage should report CIS plus the mapped frameworks.
	if len(n.Frameworks) < 2 {
		t.Errorf("framework coverage should list CIS + mapped frameworks, got %+v", n.Frameworks)
	}
	if !strings.Contains(n.Text(), "regressed") {
		t.Errorf("narrative text should mention regressions")
	}
}

func TestNarrativeSurfacesExpiringWaivers(t *testing.T) {
	rep := sampleBenchmark().Run(fixedAssessor(map[string]Status{"2.1": StatusPass, "2.2": StatusFail, "2.10": StatusPass}))
	now := time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)
	ws := NewWaivers([]Waiver{{Control: "2.2", Reason: "compensating", Expires: "2026-07-15T00:00:00Z"}})
	n := BuildNarrative(rep, NarrativeOptions{Now: now, Waivers: ws})
	if len(n.Expiring) != 1 {
		t.Fatalf("expected one expiring waiver in the narrative, got %d", len(n.Expiring))
	}
}
