package rbac

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// update regenerates the golden file when set: `go test ./internal/modules/rbac/ -update`.
var update = flag.Bool("update", false, "update golden files")

func fixtureTarget(t *testing.T, meta map[string]string) *engine.Target {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "cluster.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return &engine.Target{Type: engine.TargetFilesystem, Location: "testdata/cluster.json", Content: data, Metadata: meta}
}

func TestSupports(t *testing.T) {
	m := New()
	if !m.Supports(engine.TargetFilesystem) {
		t.Error("rbac module should support filesystem targets")
	}
	if m.Supports(engine.TargetDockerfile) || m.Supports(engine.TargetImage) {
		t.Error("rbac module should only support filesystem targets")
	}
}

// TestGolden is the deterministic end-to-end test: analyze the committed fixture,
// serialize the findings, and compare against the committed golden file.
func TestGolden(t *testing.T) {
	m := New()
	findings, err := m.Analyze(context.Background(), fixtureTarget(t, nil))
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	got, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	goldenPath := filepath.Join("testdata", "findings.golden.json")
	if *update {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("updated %s", goldenPath)
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

func TestDeterministicAcrossRuns(t *testing.T) {
	m := New()
	a, err := m.Analyze(context.Background(), fixtureTarget(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	b, err := m.Analyze(context.Background(), fixtureTarget(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) {
		t.Error("module analysis is not deterministic across runs")
	}
}

// TestEmptyTargetIsQuiet proves a filesystem target with no RBAC objects yields
// no findings, so generic filesystem scans are not polluted.
func TestEmptyTargetIsQuiet(t *testing.T) {
	m := New()
	findings, err := m.Analyze(context.Background(), &engine.Target{
		Type:    engine.TargetFilesystem,
		Content: []byte(`{"kind":"ConfigMap","metadata":{"name":"unrelated"}}`),
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("expected no findings for non-RBAC input, got %d", len(findings))
	}
}

// TestNHIFlagOffByDefault confirms the AI-age NHI feature only runs when the
// metadata flag is set — and that it does run when set.
func TestNHIFlagOffByDefault(t *testing.T) {
	m := New()

	off, err := m.Analyze(context.Background(), fixtureTarget(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range off {
		if f.RuleID == "DS-RAT-RBAC-018" {
			t.Fatal("NHI finding present without opt-in metadata flag")
		}
	}

	// With the flag on and a far-future clock, the dormant ops SA (cluster-admin)
	// must surface. The fixture SA has no lastUsedUnix, so use an over-broad, not
	// dormant, signal: ops reaches cluster-admin, blast radius large.
	on, err := m.Analyze(context.Background(), fixtureTarget(t, map[string]string{
		metaEnableNHI: "true",
		metaNowUnix:   "1000000000",
	}))
	if err != nil {
		t.Fatal(err)
	}
	var nhi bool
	for _, f := range on {
		if f.RuleID == "DS-RAT-RBAC-018" {
			nhi = true
		}
	}
	if !nhi {
		t.Error("expected an NHI (DS-RAT-RBAC-018) finding when the flag is enabled")
	}
}

func TestCommandTextAndJSON(t *testing.T) {
	// Smoke-test the exported command body on the committed fixture path.
	if code := Command([]string{"testdata/cluster.json"}); code != 0 {
		t.Errorf("Command text exit = %d, want 0", code)
	}
	if code := Command([]string{"--format", "json", "testdata/cluster.json"}); code != 0 {
		t.Errorf("Command json exit = %d, want 0", code)
	}
	if code := Command([]string{"--who-can", "get:secrets:payments", "testdata/cluster.json"}); code != 0 {
		t.Errorf("Command who-can exit = %d, want 0", code)
	}
	if code := Command([]string{"--fail-on", "CRITICAL", "testdata/cluster.json"}); code != 1 {
		t.Errorf("Command fail-on CRITICAL exit = %d, want 1 (fixture has a critical)", code)
	}
	if code := Command([]string{"/does/not/exist"}); code != 1 {
		t.Errorf("Command missing path exit = %d, want 1", code)
	}
	if code := Command([]string{}); code != 2 {
		t.Errorf("Command no-arg exit = %d, want 2", code)
	}
}
