package policy

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// update regenerates golden files: `go test ./internal/policy -update`.
var update = flag.Bool("update", false, "update golden files")

// loadPolicy compiles a policy fixture from testdata.
func loadPolicy(t *testing.T, name string) *Engine {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	eng, err := CompileBytes(data)
	if err != nil {
		t.Fatalf("compile %s: %v", name, err)
	}
	return eng
}

// baselineInput builds the end-to-end scenario the golden pins: an unsigned,
// tag-only image from a public registry, with a critical CVE and a GPL package,
// deployed as a privileged root container. It should be denied with a full,
// agent-consumable explanation.
func baselineInput(t *testing.T) *Input {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "report.json"))
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	rep, err := LoadReport(data)
	if err != nil {
		t.Fatalf("load report: %v", err)
	}
	findings := rep.EngineFindings()
	return &Input{
		Findings: findings,
		Image:    Image{Reference: rep.Target, Registry: "docker.io", Repository: "acme/api", Tag: "1.4.2"},
		Attest:   InferAttestation(findings), // no verify verdict in the report -> unsigned
		Licenses: []string{"GPL-3.0-only"},
		Workload: Workload{Present: true, Privileged: true, RunAsRoot: true},
	}
}

func TestGoldenBaselineExplanation(t *testing.T) {
	eng := loadPolicy(t, "baseline.policy.json")
	in := baselineInput(t)

	res := eng.Evaluate(in, fixedNow)
	if res.Decision != DecisionDeny {
		t.Fatalf("decision = %s, want deny", res.Decision)
	}

	ex := eng.Explain(res, in)
	got, err := json.MarshalIndent(ex, "", "  ")
	if err != nil {
		t.Fatalf("marshal explanation: %v", err)
	}
	got = append(got, '\n')

	goldenPath := filepath.Join("testdata", "baseline_explain.golden.json")
	if *update {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("explanation mismatch with golden.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	// Re-marshalling must be byte-identical: proves the explanation (and its
	// maps) serialize deterministically, which is what makes the golden stable.
	again, _ := json.MarshalIndent(eng.Explain(eng.Evaluate(in, fixedNow), in), "", "  ")
	again = append(again, '\n')
	if !bytes.Equal(got, again) {
		t.Error("explanation is not deterministic across runs")
	}
}

// TestGoldenSpecificDenials asserts the exact denial set behind the golden, so a
// future policy edit that changes which rules block is caught explicitly.
func TestGoldenSpecificDenials(t *testing.T) {
	eng := loadPolicy(t, "baseline.policy.json")
	res := eng.Evaluate(baselineInput(t), fixedNow)

	wantDeny := map[string]bool{
		"require-signature":   true,
		"cve-budget-critical": true,
		"no-privileged":       true,
		"run-as-nonroot":      true,
	}
	got := map[string]bool{}
	for _, d := range res.Denials() {
		got[d.RuleID] = true
	}
	if len(got) != len(wantDeny) {
		t.Fatalf("denials = %v, want %v", got, wantDeny)
	}
	for id := range wantDeny {
		if !got[id] {
			t.Errorf("expected denial %q, missing", id)
		}
	}

	// The high-CVE budget (5) is not exceeded by 2 highs, so it must NOT fire.
	for _, rr := range res.Rules {
		if rr.RuleID == "cve-budget-high" && rr.Matched {
			t.Error("cve-budget-high should not fire with 2 high findings")
		}
	}
}

// TestAIWorkloadPolicyDeniesUnattestedModel exercises the AI-workload starter
// policy: a model image without a signed AI-BOM is denied.
func TestAIWorkloadPolicyDeniesUnattestedModel(t *testing.T) {
	eng := loadPolicy(t, "ai-workload.policy.json")

	unattested := &Input{
		Image:  Image{Reference: "docker.io/acme/llm-model:1"},
		Attest: StaticAttestation{IsSigned: false},
	}
	if res := eng.Evaluate(unattested, fixedNow); res.Decision != DecisionDeny {
		t.Fatalf("unattested model: decision = %s, want deny", res.Decision)
	}

	attested := &Input{
		Image: Image{Reference: "docker.io/acme/llm-model:1"},
		Attest: StaticAttestation{
			IsSigned:   true,
			Predicates: []string{"https://docker-security/attestations/ai-bom/v1"},
		},
	}
	res := eng.Evaluate(attested, fixedNow)
	if res.Decision == DecisionDeny {
		t.Fatalf("attested model should not be denied, got %s", res.Decision)
	}
}
