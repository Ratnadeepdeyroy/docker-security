package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/policy"
)

var update = flag.Bool("update", false, "update golden files")

// analyze runs the module against a target carrying the given metadata.
func analyze(t *testing.T, md map[string]string) []engine.Finding {
	t.Helper()
	tgt := &engine.Target{Type: engine.TargetImage, Location: "docker.io/acme/api:1.4.2", Metadata: md}
	fs, err := New().Analyze(context.Background(), tgt)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return fs
}

func findingByRule(fs []engine.Finding, ruleID string) (engine.Finding, bool) {
	for _, f := range fs {
		if f.RuleID == ruleID {
			return f, true
		}
	}
	return engine.Finding{}, false
}

func TestRegisterAddsModule(t *testing.T) {
	// Proves the Register() hook the master calls from modules.Default() puts a
	// working policy module into the registry with the expected identity.
	r := engine.NewRegistry()
	Register(r)
	m, ok := r.Get(moduleName)
	if !ok {
		t.Fatal("policy module not registered")
	}
	if m.Name() != "policy" || len(m.Domains()) == 0 || m.Domains()[0] != "8" {
		t.Fatalf("unexpected identity: name=%q domains=%v", m.Name(), m.Domains())
	}
	if !m.Supports(engine.TargetImage) || m.Supports(engine.TargetDockerfile) {
		t.Fatal("Supports() should cover image but not dockerfile")
	}
}

func TestModuleNotConfigured(t *testing.T) {
	fs := analyze(t, map[string]string{})
	if len(fs) != 1 || fs[0].RuleID != ruleNotConfigured {
		t.Fatalf("expected a single not-configured finding, got %+v", fs)
	}
	if fs[0].Severity != engine.SeverityInfo {
		t.Fatalf("not-configured severity = %s, want INFO", fs[0].Severity)
	}
}

func TestModuleLoadError(t *testing.T) {
	fs := analyze(t, map[string]string{"policy.file": filepath.Join("testdata", "does-not-exist.json")})
	if f, ok := findingByRule(fs, ruleLoadError); !ok || f.Severity != engine.SeverityHigh {
		t.Fatalf("expected a HIGH load-error finding, got %+v", fs)
	}
}

func TestModuleDeniesUnsignedCriticalImage(t *testing.T) {
	fs := analyze(t, map[string]string{
		"policy.file":   filepath.Join("testdata", "gate.policy.json"),
		"policy.report": filepath.Join("testdata", "report.json"),
	})

	verdict, ok := findingByRule(fs, ruleVerdict)
	if !ok {
		t.Fatal("missing verdict finding")
	}
	if verdict.Metadata["decision"] != "deny" {
		t.Fatalf("verdict decision = %q, want deny", verdict.Metadata["decision"])
	}
	if verdict.Severity != engine.SeverityHigh {
		t.Fatalf("deny verdict severity = %s, want HIGH", verdict.Severity)
	}

	// Two deny rules must produce two DS-RAT-POL-100 violations.
	var violations int
	for _, f := range fs {
		if f.RuleID == ruleViolation {
			violations++
		}
	}
	if violations != 2 {
		t.Fatalf("violations = %d, want 2 (require-signature + no-critical-cves)", violations)
	}

	// The restricted-license warn rule must surface as a DS-RAT-POL-101 warning.
	if _, ok := findingByRule(fs, ruleWarning); !ok {
		t.Fatal("expected a DS-RAT-POL-101 warning for the restricted license")
	}
}

func TestModuleExplainOffByDefault(t *testing.T) {
	base := map[string]string{
		"policy.file":   filepath.Join("testdata", "gate.policy.json"),
		"policy.report": filepath.Join("testdata", "report.json"),
	}
	// Off by default: no explanation in the verdict metadata.
	v, _ := findingByRule(analyze(t, base), ruleVerdict)
	if _, has := v.Metadata["explanation"]; has {
		t.Fatal("explanation must be absent unless policy.explain=true")
	}

	// Opt in: the verdict carries a parseable, agent-consumable explanation.
	base["policy.explain"] = "true"
	v, _ = findingByRule(analyze(t, base), ruleVerdict)
	raw, has := v.Metadata["explanation"]
	if !has {
		t.Fatal("expected an explanation when policy.explain=true")
	}
	var ex policy.Explanation
	if err := json.Unmarshal([]byte(raw), &ex); err != nil {
		t.Fatalf("explanation is not valid JSON: %v", err)
	}
	if ex.Decision != policy.DecisionDeny || len(ex.Denials) != 2 {
		t.Fatalf("explanation = %+v, want deny with 2 denials", ex)
	}
	if len(ex.Remediation) == 0 {
		t.Fatal("explanation must carry a remediation to-do list")
	}
}

func TestModuleInfersSignatureFromReport(t *testing.T) {
	// A report carrying a verify PASSED verdict should satisfy require-signature
	// without any explicit policy.signed hint (cross-phase inference).
	rep := `{"target_type":"image","target":"img","findings":[
	  {"rule_id":"DS-RAT-SUP-000","module":"verify","severity":"INFO","title":"verdict","metadata":{"verdict":"PASSED"}}
	]}`
	dir := t.TempDir()
	reportPath := filepath.Join(dir, "signed-report.json")
	if err := os.WriteFile(reportPath, []byte(rep), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := analyze(t, map[string]string{
		"policy.file":   filepath.Join("testdata", "gate.policy.json"),
		"policy.report": reportPath,
	})
	v, _ := findingByRule(fs, ruleVerdict)
	if v.Metadata["decision"] != "allow" {
		t.Fatalf("decision = %q, want allow (signature inferred from report)", v.Metadata["decision"])
	}
}

func TestModuleGolden(t *testing.T) {
	fs := analyze(t, map[string]string{
		"policy.file":   filepath.Join("testdata", "gate.policy.json"),
		"policy.report": filepath.Join("testdata", "report.json"),
	})
	got, err := json.MarshalIndent(fs, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	golden := filepath.Join("testdata", "gate_findings.golden.json")
	if *update {
		if err := os.WriteFile(golden, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("findings mismatch.\n--- got ---\n%s", got)
	}
}
