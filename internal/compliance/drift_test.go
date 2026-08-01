package compliance

import "testing"

func TestDiffRegressedFixedNewRemoved(t *testing.T) {
	baseline := sampleBenchmark().Run(fixedAssessor(map[string]Status{
		"2.1":  StatusPass, // will regress
		"2.2":  StatusFail, // will be fixed
		"2.10": StatusPass, // will be removed (not in current)
	}))

	// Current run: 2.1 regressed to FAIL, 2.2 fixed to PASS, 2.10 dropped,
	// and a brand-new control 2.99 appears.
	cur := Benchmark{
		Code: "docker", Name: "CIS Docker Benchmark", Version: "1.6.0",
		Controls: []Control{
			{ID: "2.1", Title: "one", Scored: true},
			{ID: "2.2", Title: "two", Scored: true},
			{ID: "2.99", Title: "new", Scored: true},
		},
	}.Run(fixedAssessor(map[string]Status{"2.1": StatusFail, "2.2": StatusPass, "2.99": StatusPass}))

	d := Diff(baseline, cur)
	if len(d.Regressed) != 1 || d.Regressed[0].ControlID != "2.1" {
		t.Errorf("regressed = %+v, want [2.1]", d.Regressed)
	}
	if len(d.Fixed) != 1 || d.Fixed[0].ControlID != "2.2" {
		t.Errorf("fixed = %+v, want [2.2]", d.Fixed)
	}
	if len(d.New) != 1 || d.New[0].ControlID != "2.99" {
		t.Errorf("new = %+v, want [2.99]", d.New)
	}
	if len(d.Removed) != 1 || d.Removed[0].ControlID != "2.10" {
		t.Errorf("removed = %+v, want [2.10]", d.Removed)
	}
	if !d.HasDrift() {
		t.Errorf("HasDrift should be true")
	}
}

func TestDiffNilBaselineIsAllNew(t *testing.T) {
	cur := sampleBenchmark().Run(fixedAssessor(map[string]Status{"2.1": StatusPass, "2.2": StatusFail, "2.10": StatusWarn}))
	d := Diff(nil, cur)
	if len(d.New) != 3 {
		t.Errorf("nil baseline should make every control new, got %d", len(d.New))
	}
	if d.HasDrift() {
		t.Errorf("first run (all new) should not count as drift")
	}
}

func TestDiffIsDeterministic(t *testing.T) {
	baseline := sampleBenchmark().Run(fixedAssessor(map[string]Status{"2.1": StatusPass, "2.2": StatusPass, "2.10": StatusPass}))
	cur := sampleBenchmark().Run(fixedAssessor(map[string]Status{"2.1": StatusFail, "2.2": StatusFail, "2.10": StatusFail}))
	first := Diff(baseline, cur)
	for i := 0; i < 3; i++ {
		again := Diff(baseline, cur)
		if len(again.Regressed) != len(first.Regressed) {
			t.Fatalf("non-deterministic drift")
		}
		for j := range again.Regressed {
			if again.Regressed[j].ControlID != first.Regressed[j].ControlID {
				t.Fatalf("regressed order changed between runs")
			}
		}
	}
	// Regressed must be sorted numerically.
	want := []string{"2.1", "2.2", "2.10"}
	for i, e := range first.Regressed {
		if e.ControlID != want[i] {
			t.Errorf("regressed[%d] = %s, want %s", i, e.ControlID, want[i])
		}
	}
}
