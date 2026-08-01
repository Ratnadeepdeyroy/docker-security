package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// loadTestScenario reads and parses a scenario fixture, failing the test on any
// error — fixtures are part of the test, so a broken one is a test failure.
func loadTestScenario(t *testing.T, name string) *Scenario {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("open scenario: %v", err)
	}
	defer f.Close()
	sc, err := LoadScenario(f)
	if err != nil {
		t.Fatalf("load scenario %s: %v", name, err)
	}
	return sc
}

// runDefault runs the default (detect-only, no optional rules) detector over a
// scenario and returns detections with the bulky Trigger event dropped, so the
// golden focuses on detection semantics rather than echoing the input.
func runDefault(t *testing.T, sc *Scenario) []Detection {
	t.Helper()
	det := NewDetector(Options{}, sc.Images)
	dets, err := det.Run(context.Background(), NewReplaySource(sc.Events))
	if err != nil {
		t.Fatalf("detector run: %v", err)
	}
	for i := range dets {
		dets[i].Trigger = nil
	}
	return dets
}

// TestGoldenAttackScenario is the end-to-end golden test: the committed attack
// stream must produce exactly the committed detections. Run with UPDATE_GOLDEN=1
// to regenerate after an intentional rule change.
func TestGoldenAttackScenario(t *testing.T) {
	sc := loadTestScenario(t, "attack_scenario.json")
	dets := runDefault(t, sc)

	got, err := json.MarshalIndent(dets, "", "  ")
	if err != nil {
		t.Fatalf("marshal detections: %v", err)
	}
	got = append(got, '\n')

	goldenPath := filepath.Join("testdata", "attack_scenario.detections.golden.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("updated golden %s (%d detections)", goldenPath, len(dets))
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with UPDATE_GOLDEN=1 to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("detections differ from golden.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestDeterministicRerun proves the detector is deterministic: two independent
// runs over the same stream yield byte-identical output. This is the property
// the whole offline design rests on.
func TestDeterministicRerun(t *testing.T) {
	sc := loadTestScenario(t, "attack_scenario.json")
	first, err := json.Marshal(runDefault(t, sc))
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(runDefault(t, sc))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("non-deterministic detector: two runs differ")
	}
}

// TestCoreRulesFire asserts every default rule fires at least once on the
// scenario, so coverage regressions are caught even if the golden is regenerated.
func TestCoreRulesFire(t *testing.T) {
	sc := loadTestScenario(t, "attack_scenario.json")
	fired := map[string]bool{}
	for _, d := range runDefault(t, sc) {
		fired[d.RuleID] = true
	}
	for _, id := range []string{
		"DS-RAT-RT-001", "DS-RAT-RT-002", "DS-RAT-RT-003", "DS-RAT-RT-004",
		"DS-RAT-RT-005", "DS-RAT-RT-006", "DS-RAT-RT-007", "DS-RAT-RT-008",
		"DS-RAT-RT-009", "DS-RAT-RT-010",
	} {
		if !fired[id] {
			t.Errorf("expected core rule %s to fire on the attack scenario, it did not", id)
		}
	}
}

// TestOptionalRulesOffByDefault proves the intelligence-layer rules stay silent
// by default even though the scenario contains an AI-agent egress and
// unbaselined behavior — correctness never depends on them (SHARED_CONTRACT §4).
func TestOptionalRulesOffByDefault(t *testing.T) {
	sc := loadTestScenario(t, "attack_scenario.json")
	for _, d := range runDefault(t, sc) {
		if d.RuleID == "DS-RAT-RT-050" || d.RuleID == "DS-RAT-RT-100" {
			t.Errorf("optional rule %s fired by default; it must be opt-in", d.RuleID)
		}
	}
}

// TestArgsRedactedInDetections ensures no credential-shaped argv token survives
// into a detection (SHARED_CONTRACT §7: secrets never logged).
func TestArgsRedactedInDetections(t *testing.T) {
	events := []Event{{
		Seq: 1, Kind: KindProcess,
		Container: ContainerInfo{ID: "c1", ImageRef: "img"},
		Process: ProcessInfo{
			PID: 10, Exe: "/usr/local/bin/xmrig", Comm: "xmrig",
			Args:     []string{"xmrig", "--token=AKIA1234567890ABCDEFGHIJKLMNOP", "-o", "stratum+tcp://pool:4444"},
			Ancestry: []string{"/usr/sbin/nginx", "/usr/local/bin/xmrig"},
		},
	}}
	det := NewDetector(Options{}, nil)
	dets, _ := det.Run(context.Background(), NewReplaySource(events))
	if len(dets) == 0 {
		t.Fatal("expected a crypto-mining detection")
	}
	for _, d := range dets {
		for _, a := range d.Process.Args {
			if a == "--token=AKIA1234567890ABCDEFGHIJKLMNOP" {
				t.Errorf("secret token survived redaction in detection args: %q", a)
			}
		}
	}
}
