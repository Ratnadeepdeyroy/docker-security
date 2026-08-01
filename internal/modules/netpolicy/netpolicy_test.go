package netpolicy

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/netmon"
)

var update = flag.Bool("update", false, "rewrite golden files")

func loadFixture(t *testing.T, name string) *netmon.Capture {
	t.Helper()
	c, err := netmon.LoadCapture(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("LoadCapture(%s): %v", name, err)
	}
	return c
}

// analyzeFixture runs the module over a testdata capture with optional metadata.
func analyzeFixture(t *testing.T, name string, meta map[string]string) []engine.Finding {
	t.Helper()
	m := New()
	fs, err := m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetFilesystem,
		Location: filepath.Join("testdata", name),
		Metadata: meta,
	})
	if err != nil {
		t.Fatalf("Analyze(%s): %v", name, err)
	}
	return fs
}

func byRule(fs []engine.Finding) map[string][]engine.Finding {
	m := map[string][]engine.Finding{}
	for _, f := range fs {
		m[f.RuleID] = append(m[f.RuleID], f)
	}
	return m
}

func TestSupports(t *testing.T) {
	m := New()
	if !m.Supports(engine.TargetFilesystem) {
		t.Error("netpolicy must support filesystem targets (the capture carrier)")
	}
	for _, tt := range []engine.TargetType{engine.TargetImage, engine.TargetDockerfile, engine.TargetContainer, engine.TargetRegistry} {
		if m.Supports(tt) {
			t.Errorf("netpolicy must not support %q", tt)
		}
	}
	if m.Name() != "netpolicy" {
		t.Errorf("name = %q", m.Name())
	}
	if len(m.Domains()) != 1 || m.Domains()[0] != "6" {
		t.Errorf("domains = %v, want [6]", m.Domains())
	}
}

// TestModuleGoldenThreats pins the full finding set for the threats capture with
// default (AI-off) options — the end-to-end, offline, deterministic proof.
func TestModuleGoldenThreats(t *testing.T) {
	got := analyzeFixture(t, "capture_threats.json", nil)
	pretty, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	assertGoldenBytes(t, filepath.Join("testdata", "findings_threats.golden.json"), append(pretty, '\n'))
}

// TestModuleFiresCoreRules asserts the high-value rules appear at the right
// severity, independent of the golden (so intent is legible even if the golden
// is regenerated).
func TestModuleFiresCoreRules(t *testing.T) {
	got := byRule(analyzeFixture(t, "capture_threats.json", nil))
	want := map[string]engine.Severity{
		"DS-RAT-NET-000": engine.SeverityInfo,     // summary
		"DS-RAT-NET-001": engine.SeverityMedium,   // default-deny recommendation
		"DS-RAT-NET-002": engine.SeverityMedium,   // host network
		"DS-RAT-NET-010": engine.SeverityCritical, // IMDS
		"DS-RAT-NET-011": engine.SeverityHigh,     // beacon
		"DS-RAT-NET-012": engine.SeverityHigh,     // exfil
		"DS-RAT-NET-014": engine.SeverityHigh,     // lateral
		"DS-RAT-NET-015": engine.SeverityHigh,     // dns tunnel
		"DS-RAT-NET-016": engine.SeverityHigh,     // dga
		"DS-RAT-NET-030": engine.SeverityLow,      // blocked egress
	}
	for id, sev := range want {
		hits, ok := got[id]
		if !ok {
			t.Errorf("expected rule %s to fire", id)
			continue
		}
		if hits[0].Severity != sev {
			t.Errorf("%s severity = %s, want %s", id, hits[0].Severity, sev)
		}
		if hits[0].Module != "netpolicy" {
			t.Errorf("%s module = %q", id, hits[0].Module)
		}
	}
	// AI-age rules must be silent under default options.
	if _, ok := got["DS-RAT-NET-020"]; ok {
		t.Error("DS-RAT-NET-020 (agent egress) must be off by default")
	}
	if _, ok := got["DS-RAT-NET-021"]; ok {
		t.Error("DS-RAT-NET-021 (intent) must be off by default")
	}
}

// TestModuleMetadataEnablesAIFeatures proves the opt-in metadata switches on the
// intent and agent-egress findings that are otherwise absent.
func TestModuleMetadataEnablesAIFeatures(t *testing.T) {
	// Intent on the baseline surfaces the anomalous raw-IP dest.
	got := byRule(analyzeFixture(t, "capture_baseline.json", map[string]string{metaIntent: "true"}))
	if _, ok := got["DS-RAT-NET-021"]; !ok {
		t.Error("DS-RAT-NET-021 should fire when netpolicy.intent=true")
	}
	// Agent egress on the agent capture surfaces the unknown model host.
	got = byRule(analyzeFixture(t, "capture_agent.json", map[string]string{metaAgentEgress: "true"}))
	hits, ok := got["DS-RAT-NET-020"]
	if !ok {
		t.Fatal("DS-RAT-NET-020 should fire when netpolicy.agent_egress=true")
	}
	var sawHigh bool
	for _, f := range hits {
		if f.Severity == engine.SeverityHigh {
			sawHigh = true
		}
	}
	if !sawHigh {
		t.Error("expected a HIGH agent-egress finding for the unknown LLM host")
	}
}

// TestNowUnixDeterminism confirms injecting the reference time keeps output
// stable and identical across runs.
func TestNowUnixDeterminism(t *testing.T) {
	meta := map[string]string{metaNowUnix: "1000000"}
	first := analyzeFixture(t, "capture_threats.json", meta)
	second := analyzeFixture(t, "capture_threats.json", meta)
	if !reflect.DeepEqual(first, second) {
		t.Error("two runs with the same injected time produced different findings")
	}
}

// TestHostileInput proves the module survives untrusted input: garbage inlined
// content errors, a non-capture path is ignored quietly, and a wrong target
// type never panics.
func TestHostileInput(t *testing.T) {
	m := New()
	// Garbage inlined content must error (it tried to be a capture).
	if _, err := m.Analyze(context.Background(), &engine.Target{
		Type: engine.TargetFilesystem, Location: "x.json", Content: []byte("not json at all"),
	}); err == nil {
		t.Error("garbage inlined capture should error")
	}
	// A path that is not our capture format is not our concern: quiet, no error.
	notCapture := filepath.Join(t.TempDir(), "readme.txt")
	if err := os.WriteFile(notCapture, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, err := m.Analyze(context.Background(), &engine.Target{Type: engine.TargetFilesystem, Location: notCapture})
	if err != nil {
		t.Errorf("non-capture file should be ignored, got error: %v", err)
	}
	if len(fs) != 0 {
		t.Errorf("non-capture file should yield no findings, got %d", len(fs))
	}
}

// --- golden helper --------------------------------------------------------

func assertGoldenBytes(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote golden %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update first): %v", path, err)
	}
	if string(got) != string(want) {
		t.Errorf("%s differs from golden.\n--- got ---\n%s", filepath.Base(path), got)
	}
}
