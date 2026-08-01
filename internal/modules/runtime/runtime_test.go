package runtime

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	rt "github.com/Ratnadeepdeyroy/docker-security/internal/runtime"
)

func containerTarget(location string, meta map[string]string) *engine.Target {
	if meta == nil {
		meta = map[string]string{}
	}
	return &engine.Target{Type: engine.TargetContainer, Location: location, Metadata: meta}
}

func analyze(t *testing.T, target *engine.Target) []engine.Finding {
	t.Helper()
	fs, err := New().Analyze(context.Background(), target)
	if err != nil {
		t.Fatalf("analyze: %v", err)
	}
	return fs
}

func ruleIDs(fs []engine.Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.RuleID] = true
	}
	return m
}

func TestModuleContract(t *testing.T) {
	m := New()
	if m.Name() != "runtime" {
		t.Errorf("name = %q", m.Name())
	}
	if !m.Supports(engine.TargetContainer) {
		t.Error("must support container targets")
	}
	if m.Supports(engine.TargetDockerfile) {
		t.Error("must not support dockerfile targets")
	}
	if len(m.Domains()) == 0 {
		t.Error("must declare domains")
	}
}

func TestModuleSilentWithoutTelemetry(t *testing.T) {
	// A container scan with no runtime telemetry supplied yields no findings.
	fs := analyze(t, containerTarget("c-web-1", nil))
	if len(fs) != 0 {
		t.Errorf("expected no findings without telemetry, got %d", len(fs))
	}
}

func TestModuleProjectsDetections(t *testing.T) {
	events := filepath.Join("testdata", "container_telemetry.json")
	// Scope to the web container.
	fs := analyze(t, containerTarget("c-web-1", map[string]string{metaEvents: events}))
	ids := ruleIDs(fs)

	// Summary always present.
	if !ids["DS-RAT-RT-000"] {
		t.Error("expected a DS-RAT-RT-000 summary finding")
	}
	// Core detections for the web container.
	for _, want := range []string{"DS-RAT-RT-001", "DS-RAT-RT-002", "DS-RAT-RT-005"} {
		if !ids[want] {
			t.Errorf("expected finding %s for the web container", want)
		}
	}
	// Every finding carries the module name, an ATT&CK technique, and a severity.
	for _, f := range fs {
		if f.Module != "runtime" {
			t.Errorf("finding %s has module %q", f.RuleID, f.Module)
		}
		if f.RuleID != "DS-RAT-RT-000" {
			if f.Metadata["attack_technique"] == "" {
				t.Errorf("finding %s missing attack_technique metadata", f.RuleID)
			}
			if f.Remediation == "" {
				t.Errorf("finding %s missing remediation", f.RuleID)
			}
		}
	}
}

func TestModuleScopesToContainer(t *testing.T) {
	events := filepath.Join("testdata", "container_telemetry.json")
	// Scoping to the web container must NOT include the agent container's events;
	// and since the agent rule is off by default, the agent produces nothing anyway.
	fs := analyze(t, containerTarget("c-web-1", map[string]string{metaEvents: events}))
	for _, f := range fs {
		if f.Resource == "assistant" {
			t.Errorf("web-scoped scan leaked an agent-container finding: %s", f.RuleID)
		}
	}
}

func TestModuleAgentRuleOffByDefault(t *testing.T) {
	events := filepath.Join("testdata", "container_telemetry.json")
	// Scope to the agent container without enabling the agent rule → only the
	// summary (no DS-RAT-RT-100), proving off-by-default at the module boundary.
	fs := analyze(t, containerTarget("c-agent-1", map[string]string{metaEvents: events}))
	if ruleIDs(fs)["DS-RAT-RT-100"] {
		t.Error("agent rule fired without runtime.enable_agent")
	}
}

func TestModuleAgentRuleEnabled(t *testing.T) {
	events := filepath.Join("testdata", "container_telemetry.json")
	fs := analyze(t, containerTarget("c-agent-1", map[string]string{
		metaEvents:      events,
		metaEnableAgent: "true",
	}))
	if !ruleIDs(fs)["DS-RAT-RT-100"] {
		t.Error("expected DS-RAT-RT-100 when runtime.enable_agent=true and the workload is an AI agent")
	}
}

func TestModuleAnomalyRequiresBaseline(t *testing.T) {
	events := filepath.Join("testdata", "container_telemetry.json")
	_, err := New().Analyze(context.Background(), containerTarget("c-web-1", map[string]string{
		metaEvents:        events,
		metaEnableAnomaly: "true", // but no baseline path → must error clearly
	}))
	if err == nil {
		t.Error("expected an error when anomaly is enabled without a baseline")
	}
}

func TestModuleBadTelemetryErrors(t *testing.T) {
	_, err := New().Analyze(context.Background(), containerTarget("c-web-1", map[string]string{
		metaEvents: filepath.Join("testdata", "does-not-exist.json"),
	}))
	if err == nil {
		t.Error("expected an error for a missing telemetry file")
	}
}

func TestModuleInlineTelemetry(t *testing.T) {
	// Telemetry can be inlined in Target.Content instead of a file path.
	data, err := os.ReadFile(filepath.Join("testdata", "container_telemetry.json"))
	if err != nil {
		t.Fatal(err)
	}
	tgt := &engine.Target{Type: engine.TargetContainer, Location: "c-web-1", Content: data}
	fs := analyze(t, tgt)
	if !ruleIDs(fs)["DS-RAT-RT-001"] {
		t.Error("inline telemetry should be analyzed just like a file")
	}
}

func TestModuleEgressAllowlist(t *testing.T) {
	// A scenario where the workload egresses to a non-suspicious port outside an
	// allowlist should surface DS-RAT-RT-007 only when the allowlist is configured.
	scenario := `{"version":1,"images":[{"image_id":"i","binaries":["/app"]}],"events":[
		{"seq":1,"kind":"network","container":{"id":"c1","name":"svc","image_id":"i"},"process":{"pid":1,"exe":"/app"},"network":{"op":"connect","remote_ip":"203.0.113.9","remote_port":8080,"direction":"egress"}}
	]}`
	base := map[string]string{metaEnableAgent: ""}
	// Without an allowlist: normal port, no hard signal → no egress finding.
	tgt := &engine.Target{Type: engine.TargetContainer, Location: "c1", Content: []byte(scenario), Metadata: base}
	if ruleIDs(analyze(t, tgt))["DS-RAT-RT-007"] {
		t.Error("no allowlist configured → benign egress must not fire DS-RAT-RT-007")
	}
	// With an allowlist that excludes the destination → flagged.
	tgt.Metadata = map[string]string{metaEgressAllow: "10.0.0.0/8, api.internal"}
	if !ruleIDs(analyze(t, tgt))["DS-RAT-RT-007"] {
		t.Error("egress outside the configured allowlist should fire DS-RAT-RT-007")
	}
}

func TestModuleAnomalyWithBaseline(t *testing.T) {
	// Learn a baseline, write it, then drive the module with anomaly enabled and
	// a novel exe — DS-RAT-RT-050 should fire. Exercises the full metadata path.
	img := "sha256:svc"
	learn := []rt.Event{{Seq: 1, Kind: rt.KindProcess, Container: rt.ContainerInfo{ID: "c1", ImageID: img, ImageRef: "svc:1"}, Process: rt.ProcessInfo{PID: 1, Exe: "/app/svc"}}}
	det := rt.NewDetector(rt.Options{EnableAnomaly: true}, nil)
	if _, err := det.Run(context.Background(), rt.NewReplaySource(learn)); err != nil {
		t.Fatal(err)
	}
	baseline := det.Baseline()
	dir := t.TempDir()
	bpath := filepath.Join(dir, "baseline.json")
	bdata, _ := json.Marshal(baseline)
	if err := os.WriteFile(bpath, bdata, 0o644); err != nil {
		t.Fatal(err)
	}

	scenario := `{"version":1,"events":[
		{"seq":1,"kind":"process","container":{"id":"c1","image_id":"sha256:svc","image_ref":"svc:1"},"process":{"pid":9,"exe":"/tmp/evil"}}
	]}`
	tgt := &engine.Target{Type: engine.TargetContainer, Location: "c1", Content: []byte(scenario),
		Metadata: map[string]string{metaEnableAnomaly: "true", metaBaseline: bpath}}
	if !ruleIDs(analyze(t, tgt))["DS-RAT-RT-050"] {
		t.Error("expected DS-RAT-RT-050 for a novel exe with anomaly enabled and a baseline loaded")
	}
}

func TestModuleDeterministic(t *testing.T) {
	events := filepath.Join("testdata", "container_telemetry.json")
	tgt := containerTarget("c-web-1", map[string]string{metaEvents: events})
	first := analyze(t, tgt)
	second := analyze(t, tgt)
	if len(first) != len(second) {
		t.Fatalf("nondeterministic finding count: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].RuleID != second[i].RuleID || first[i].Title != second[i].Title {
			t.Fatalf("finding %d differs between runs", i)
		}
	}
}
