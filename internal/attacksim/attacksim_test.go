package attacksim

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// authorized returns Options that pass the opt-in gate, for tests that need a run.
func authorized() Options {
	return Options{Authorized: true, Acknowledgement: AckPhrase()}
}

// TestRunRequiresAuthorization is the safety property: the harness refuses to run
// without an explicit, correct acknowledgement — a stray bool is not enough.
func TestRunRequiresAuthorization(t *testing.T) {
	ctrls := NewControlSet(ReferenceAdmissionControl(), ReferenceDetectionControl())

	if _, err := Run(context.Background(), Builtin(), ctrls, Options{}); err != ErrNotAuthorized {
		t.Errorf("zero Options should be unauthorized, got err=%v", err)
	}
	if _, err := Run(context.Background(), Builtin(), ctrls, Options{Authorized: true}); err != ErrNotAuthorized {
		t.Errorf("Authorized without acknowledgement should fail, got err=%v", err)
	}
	if _, err := Run(context.Background(), Builtin(), ctrls, Options{Acknowledgement: AckPhrase()}); err != ErrNotAuthorized {
		t.Errorf("acknowledgement without Authorized should fail, got err=%v", err)
	}
	if _, err := Run(context.Background(), Builtin(), ctrls, authorized()); err != nil {
		t.Errorf("correct opt-in should run, got err=%v", err)
	}
}

// TestReferenceControlsValidateEverything proves that when the reference controls
// are present, every curated scenario is caught — the defenses hold.
func TestReferenceControlsValidateEverything(t *testing.T) {
	ctrls := NewControlSet(ReferenceAdmissionControl(), ReferenceDetectionControl())
	rep, err := Run(context.Background(), Builtin(), ctrls, authorized())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total != 10 {
		t.Errorf("expected 10 scenarios, got %d", rep.Total)
	}
	if rep.Gaps != 0 {
		for _, r := range rep.Results {
			if r.Gap {
				t.Errorf("unexpected gap: %s (%s)", r.Scenario.ID, r.Scenario.Name)
			}
		}
	}
	if rep.Validated != rep.Total {
		t.Errorf("validated %d of %d; want all", rep.Validated, rep.Total)
	}
}

// TestNoControlsIsAllGaps proves the harness reports a gap for every scenario
// when there is nothing defending — the "are we actually protected?" signal.
func TestNoControlsIsAllGaps(t *testing.T) {
	rep, err := Run(context.Background(), Builtin(), NewControlSet(), authorized())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Gaps != rep.Total || rep.Validated != 0 {
		t.Errorf("empty control set should be all gaps; got validated=%d gaps=%d total=%d", rep.Validated, rep.Gaps, rep.Total)
	}
}

// TestFixtureControlsFindRecordedGaps loads recorded Phase 4/5 controls (the stub
// for phases that don't exist yet) and asserts the harness detects exactly the
// gaps those recordings encode: T1613 (admission) and T1059 (detection).
func TestFixtureControlsFindRecordedGaps(t *testing.T) {
	adm := loadCtrl(t, "phase4_admission.recorded.json")
	det := loadCtrl(t, "phase5_detection.recorded.json")
	rep, err := Run(context.Background(), Builtin(), NewControlSet(adm, det), authorized())
	if err != nil {
		t.Fatal(err)
	}
	gaps := map[string]bool{}
	for _, r := range rep.Results {
		if r.Gap {
			gaps[r.Scenario.ID] = true
		}
	}
	// DS-RAT-ATK-006 is T1613 (admission gap); DS-RAT-ATK-010 is T1059 (detection gap).
	if !gaps["DS-RAT-ATK-006"] || !gaps["DS-RAT-ATK-010"] {
		t.Errorf("expected gaps at DS-RAT-ATK-006 and DS-RAT-ATK-010; got %v", gaps)
	}
	if gaps["DS-RAT-ATK-001"] {
		t.Error("DS-RAT-ATK-001 (T1610) should be validated by the recorded admission control")
	}
	if rep.Gaps != 2 {
		t.Errorf("expected exactly 2 recorded gaps, got %d", rep.Gaps)
	}
}

// TestDeterministicOrdering proves results are ID-sorted and stable across runs.
func TestDeterministicOrdering(t *testing.T) {
	ctrls := NewControlSet(ReferenceAdmissionControl(), ReferenceDetectionControl())
	a, _ := Run(context.Background(), Builtin(), ctrls, authorized())
	b, _ := Run(context.Background(), Builtin(), ctrls, authorized())
	if len(a.Results) != len(b.Results) {
		t.Fatal("run length differs")
	}
	for i := range a.Results {
		if a.Results[i].Scenario.ID != b.Results[i].Scenario.ID {
			t.Fatalf("ordering differs at %d: %s vs %s", i, a.Results[i].Scenario.ID, b.Results[i].Scenario.ID)
		}
		if i > 0 && a.Results[i-1].Scenario.ID > a.Results[i].Scenario.ID {
			t.Errorf("results not sorted by ID at %d", i)
		}
	}
}

func TestOnlyFilter(t *testing.T) {
	ctrls := NewControlSet(ReferenceAdmissionControl())
	rep, err := Run(context.Background(), Builtin(), ctrls, Options{
		Authorized: true, Acknowledgement: AckPhrase(), Only: []string{"DS-RAT-ATK-001", "DS-RAT-ATK-004"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total != 2 {
		t.Errorf("Only filter should select 2 scenarios, got %d", rep.Total)
	}
}

// --- Continuous control-validation (AI-age feature) ------------------------

// TestBaselineRegressionDetected proves the regression detector surfaces a
// control that used to fire and now does not — a silent detection is an incident.
func TestBaselineRegressionDetected(t *testing.T) {
	full := NewControlSet(ReferenceAdmissionControl(), ReferenceDetectionControl())
	good, _ := Run(context.Background(), Builtin(), full, authorized())
	baseline := BaselineFrom(good)
	if len(baseline.Fired) != good.Total {
		t.Fatalf("baseline should cover all scenarios")
	}

	// Now detection has regressed (removed), so every detection scenario goes
	// silent. Those must show up as regressions; admission scenarios must not.
	degraded, _ := Run(context.Background(), Builtin(), NewControlSet(ReferenceAdmissionControl()), authorized())
	regs := CompareBaseline(degraded, baseline)
	if len(regs) == 0 {
		t.Fatal("expected regressions when detection control was removed")
	}
	for _, r := range regs {
		if r.ScenarioID == "" {
			t.Error("regression missing scenario id")
		}
		if !r.WasFiring || r.NowFiring {
			t.Errorf("regression %s should be was-firing->now-silent, got was=%v now=%v", r.ScenarioID, r.WasFiring, r.NowFiring)
		}
	}
}

// TestNoRegressionWhenControlsImprove proves that newly-firing controls are NOT
// reported as regressions (improvements are good news, not alerts).
func TestNoRegressionWhenControlsImprove(t *testing.T) {
	weak, _ := Run(context.Background(), Builtin(), NewControlSet(ReferenceAdmissionControl()), authorized())
	baseline := BaselineFrom(weak)
	strong, _ := Run(context.Background(), Builtin(), NewControlSet(ReferenceAdmissionControl(), ReferenceDetectionControl()), authorized())
	if regs := CompareBaseline(strong, baseline); len(regs) != 0 {
		t.Errorf("improvements must not be flagged as regressions; got %d", len(regs))
	}
}

func loadCtrl(t *testing.T, name string) *FixtureControl {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	c, err := LoadFixtureControl(data)
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return c
}
