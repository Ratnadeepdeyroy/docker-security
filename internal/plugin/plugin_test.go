package plugin

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

func dockerfileTarget() *engine.Target {
	return &engine.Target{Type: engine.TargetDockerfile, Location: "Dockerfile", Content: []byte("FROM ubuntu:latest")}
}

// --- Real subprocess tests (require /bin/sh; unix dev/CI) ----------------

func TestEchoPlugin_LoadsAndContributesFinding(t *testing.T) {
	p, err := Load(filepath.Join("testdata", "plugins", "echo.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !p.Supports(engine.TargetDockerfile) {
		t.Fatal("echo plugin should support dockerfile targets")
	}
	findings, err := p.Analyze(context.Background(), dockerfileTarget())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "DS-PLUGIN-ECHO-001" {
		t.Errorf("rule id = %q", f.RuleID)
	}
	// Module is stamped from the manifest, not the wire payload — plugins cannot spoof.
	if f.Module != "echo-linter" {
		t.Errorf("module = %q, want echo-linter", f.Module)
	}
	if f.Severity != engine.SeverityMedium {
		t.Errorf("severity = %v, want MEDIUM", f.Severity)
	}
}

func TestCrashPlugin_ContainedAsModuleError(t *testing.T) {
	p, err := Load(filepath.Join("testdata", "plugins", "crash.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = p.Analyze(context.Background(), dockerfileTarget())
	if err == nil {
		t.Fatal("expected an error from a crashing plugin")
	}

	// End-to-end: a crashing plugin registered beside a healthy module must not
	// take down the run — the good finding survives and the crash is a module error.
	reg := engine.NewRegistry()
	reg.Register(healthyModule{})
	reg.Register(p)
	rep := engine.New(reg).Run(context.Background(), dockerfileTarget())
	if len(rep.Findings) != 1 || rep.Findings[0].RuleID != "DS-RAT-OK-1" {
		t.Errorf("healthy finding lost when plugin crashed: %+v", rep.Findings)
	}
	var sawErr bool
	for _, mr := range rep.ModuleRuns {
		if mr.Module == "crash-plugin" && mr.Error != "" {
			sawErr = true
		}
	}
	if !sawErr {
		t.Errorf("crash plugin should have recorded a module error: %+v", rep.ModuleRuns)
	}
}

func TestSlowPlugin_TimesOut(t *testing.T) {
	p, err := Load(filepath.Join("testdata", "plugins", "slow.json"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = p.Analyze(context.Background(), dockerfileTarget())
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

// healthyModule is a well-behaved built-in used to prove crash isolation.
type healthyModule struct{}

func (healthyModule) Name() string                    { return "healthy" }
func (healthyModule) Description() string             { return "ok" }
func (healthyModule) Domains() []string               { return []string{"0"} }
func (healthyModule) Supports(engine.TargetType) bool { return true }
func (healthyModule) Analyze(context.Context, *engine.Target) ([]engine.Finding, error) {
	return []engine.Finding{{RuleID: "DS-RAT-OK-1", Module: "healthy", Severity: engine.SeverityLow, Title: "ok"}}, nil
}

// --- Loading & validation ------------------------------------------------

func TestLoadDir_LoadsAllValidManifests(t *testing.T) {
	h, err := LoadDir(filepath.Join("testdata", "plugins"))
	if err != nil {
		t.Fatalf("LoadDir returned error for all-valid dir: %v", err)
	}
	if len(h.Plugins()) != 3 {
		t.Fatalf("want 3 plugins (echo, crash, slow), got %d", len(h.Plugins()))
	}
	// Sorted by name: crash-plugin, echo-linter, slow-plugin.
	if h.Plugins()[0].Name() != "crash-plugin" {
		t.Errorf("plugins not name-sorted: %s first", h.Plugins()[0].Name())
	}
}

func TestLoadDir_SkipsInvalidManifestButKeepsValid(t *testing.T) {
	dir := t.TempDir()
	// One valid manifest (no executable needed — we only load, not run).
	os.WriteFile(filepath.Join(dir, "good.json"), []byte(`{"name":"good","exec":["/bin/echo"]}`), 0o644)
	// One invalid: missing exec.
	os.WriteFile(filepath.Join(dir, "bad.json"), []byte(`{"name":"bad"}`), 0o644)
	// One invalid: unknown field (strict decoding).
	os.WriteFile(filepath.Join(dir, "weird.json"), []byte(`{"name":"weird","exec":["/bin/echo"],"mystery":true}`), 0o644)

	h, err := LoadDir(dir)
	if err == nil || !strings.Contains(err.Error(), "skipped") {
		t.Fatalf("expected a skipped-manifest error, got %v", err)
	}
	if len(h.Plugins()) != 1 || h.Plugins()[0].Name() != "good" {
		t.Errorf("only the valid manifest should load, got %+v", h.Plugins())
	}
}

func TestLoadDir_MissingDirIsEmptyNotError(t *testing.T) {
	h, err := LoadDir(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Errorf("missing plugin dir should be empty, not an error: %v", err)
	}
	if len(h.Plugins()) != 0 {
		t.Errorf("want 0 plugins, got %d", len(h.Plugins()))
	}
}

func TestLoad_RejectsMissingExecPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "m.json")
	os.WriteFile(path, []byte(`{"name":"x","exec":["./nope.sh"]}`), 0o644)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for a relative exec path that does not exist")
	}
}

func TestRegisterDir_RegistersIntoRegistry(t *testing.T) {
	reg := engine.NewRegistry()
	_ = RegisterDir(reg, filepath.Join("testdata", "plugins"))
	if _, ok := reg.Get("echo-linter"); !ok {
		t.Error("echo-linter not registered")
	}
}

// --- Codec / projection via a fake runner (no subprocess) ----------------

type fakeRunner struct {
	out []byte
	err error
}

func (f fakeRunner) run(context.Context, []string, int, []byte) ([]byte, error) {
	return f.out, f.err
}

func TestProject_ForcesModuleAndDefaultsRuleID(t *testing.T) {
	p := &Plugin{
		manifest: Manifest{Name: "my plugin", TargetTypes: []string{"dockerfile"}},
		runner:   fakeRunner{out: []byte(`{"findings":[{"severity":"high","title":"no rule id"}]}`)},
	}
	fs, err := p.Analyze(context.Background(), dockerfileTarget())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if fs[0].Module != "my plugin" {
		t.Errorf("module = %q", fs[0].Module)
	}
	// A missing rule id is synthesized from the sanitized plugin name.
	if fs[0].RuleID != "DS-RAT-PLUGIN-MY-PLUGIN-001" {
		t.Errorf("synth rule id = %q", fs[0].RuleID)
	}
}

func TestAnalyze_PluginReportedErrorSurfaces(t *testing.T) {
	p := &Plugin{
		manifest: Manifest{Name: "p"},
		runner:   fakeRunner{out: []byte(`{"error":"cannot read target"}`)},
	}
	if _, err := p.Analyze(context.Background(), dockerfileTarget()); err == nil {
		t.Fatal("expected plugin-reported error to surface")
	}
}

func TestAnalyze_MalformedOutputIsError(t *testing.T) {
	p := &Plugin{manifest: Manifest{Name: "p"}, runner: fakeRunner{out: []byte("not json")}}
	if _, err := p.Analyze(context.Background(), dockerfileTarget()); err == nil {
		t.Fatal("expected malformed-output error")
	}
}
