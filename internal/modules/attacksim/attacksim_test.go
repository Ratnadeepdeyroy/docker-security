package attacksim

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	simlib "github.com/Ratnadeepdeyroy/docker-security/internal/attacksim"
	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

var update = flag.Bool("update", false, "update golden files")

func TestSupports(t *testing.T) {
	m := New()
	if !m.Supports(engine.TargetFilesystem) || !m.Supports(engine.TargetContainer) {
		t.Error("attacksim should support filesystem and container targets")
	}
	if m.Supports(engine.TargetDockerfile) {
		t.Error("attacksim should not support dockerfile targets")
	}
}

// TestOffByDefault is the safety property at the module boundary: without the
// authorization acknowledgement in metadata, the module produces nothing.
func TestOffByDefault(t *testing.T) {
	m := New()
	findings, err := m.Analyze(context.Background(), &engine.Target{Type: engine.TargetFilesystem})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("module must be inert without authorization; got %d findings", len(findings))
	}

	// Even a truthy-but-wrong value must not trigger it.
	findings, err = m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetFilesystem,
		Metadata: map[string]string{metaAuthorize: "true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Errorf("wrong acknowledgement must not authorize; got %d findings", len(findings))
	}
}

// TestReferenceControlsNoGaps proves that with the built-in reference controls
// (no controls-dir), every scenario is validated and only the INFO summary is
// emitted — no gap findings.
func TestReferenceControlsNoGaps(t *testing.T) {
	m := New()
	findings, err := m.Analyze(context.Background(), authorizedTarget(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != "DS-RAT-ATK-000" {
		t.Fatalf("expected only the DS-RAT-ATK-000 summary with reference controls; got %d findings", len(findings))
	}
	if findings[0].Metadata["gaps"] != "0" {
		t.Errorf("reference controls should leave zero gaps; got %q", findings[0].Metadata["gaps"])
	}
}

// TestGolden runs against the recorded Phase 4/5 controls (the stub) and compares
// the projected findings to the committed golden file.
func TestGolden(t *testing.T) {
	m := New()
	findings, err := m.Analyze(context.Background(), authorizedTarget(map[string]string{
		metaControlsDir: "testdata/controls",
	}))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.MarshalIndent(findings, "", "  ")
	got = append(got, '\n')

	goldenPath := filepath.Join("testdata", "findings.golden.json")
	if *update {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update first): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("findings do not match golden.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// TestGapFindingsFromRecordedControls asserts the specific gaps the recorded
// controls encode surface as findings at the scenario severity.
func TestGapFindingsFromRecordedControls(t *testing.T) {
	m := New()
	findings, err := m.Analyze(context.Background(), authorizedTarget(map[string]string{metaControlsDir: "testdata/controls"}))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]engine.Finding{}
	for _, f := range findings {
		byID[f.RuleID] = f
	}
	// DS-RAT-ATK-006 (T1613 admission) and DS-RAT-ATK-010 (T1059 detection) are the
	// recorded gaps; DS-RAT-ATK-010 is declared CRITICAL.
	if _, ok := byID["DS-RAT-ATK-006"]; !ok {
		t.Error("expected DS-RAT-ATK-006 gap finding")
	}
	if f, ok := byID["DS-RAT-ATK-010"]; !ok {
		t.Error("expected DS-RAT-ATK-010 gap finding")
	} else if f.Severity != engine.SeverityCritical {
		t.Errorf("DS-RAT-ATK-010 severity = %s, want CRITICAL", f.Severity)
	}
	// A validated scenario must NOT appear as a finding.
	if _, ok := byID["DS-RAT-ATK-001"]; ok {
		t.Error("DS-RAT-ATK-001 was validated by the recorded control; it must not be a finding")
	}
}

// TestRegressionFinding proves the baseline-regression (AI-age) path emits a
// finding when a previously-firing control goes silent.
func TestRegressionFinding(t *testing.T) {
	// Baseline where every scenario fired (the "good" past state).
	baseline := simlib.Baseline{Fired: map[string]bool{}}
	for _, sc := range simlib.Builtin() {
		baseline.Fired[sc.ID] = true
	}
	data, _ := json.Marshal(baseline)
	dir := t.TempDir()
	bpath := filepath.Join(dir, "baseline.json")
	if err := os.WriteFile(bpath, data, 0o644); err != nil {
		t.Fatal(err)
	}

	m := New()
	findings, err := m.Analyze(context.Background(), authorizedTarget(map[string]string{
		metaControlsDir: "testdata/controls", // recorded controls => DS-RAT-ATK-006 & 010 now silent
		metaBaseline:    bpath,
	}))
	if err != nil {
		t.Fatal(err)
	}
	var regressions int
	for _, f := range findings {
		if f.Metadata["regression"] == "true" {
			regressions++
		}
	}
	if regressions == 0 {
		t.Error("expected at least one regression finding when baseline expected all controls firing")
	}
}

// TestCommand smoke-tests the exported `dsecrat validate` command body: refusal
// without acknowledgement, a clean run against reference controls, and a
// gap-detecting run against recorded controls (which must exit non-zero).
func TestCommand(t *testing.T) {
	if code := Command([]string{}); code != 3 {
		t.Errorf("validate without --i-acknowledge exit = %d, want 3 (refused)", code)
	}
	if code := Command([]string{"--i-acknowledge"}); code != 0 {
		t.Errorf("validate with reference controls exit = %d, want 0 (no gaps)", code)
	}
	if code := Command([]string{"--i-acknowledge", "--controls-dir", "testdata/controls"}); code != 1 {
		t.Errorf("validate with recorded controls exit = %d, want 1 (gaps present)", code)
	}
}

// --- helpers ---------------------------------------------------------------

func authorizedTarget(extra map[string]string) *engine.Target {
	meta := map[string]string{metaAuthorize: simlib.AckPhrase()}
	for k, v := range extra {
		meta[k] = v
	}
	return &engine.Target{Type: engine.TargetFilesystem, Location: "test-env", Metadata: meta}
}
