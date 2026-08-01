package harden

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

// update rewrites golden files. Run:
//
//	go test ./internal/modules/harden/ -run Golden -update
//
// then review the diff — the golden is a reviewed baseline, not whatever the
// code happens to emit.
var update = flag.Bool("update", false, "rewrite golden files")

func TestSupports(t *testing.T) {
	m := New()
	if !m.Supports(engine.TargetContainer) {
		t.Error("harden must support container targets")
	}
	for _, tt := range []engine.TargetType{engine.TargetDockerfile, engine.TargetImage, engine.TargetFilesystem, engine.TargetRegistry} {
		if m.Supports(tt) {
			t.Errorf("harden must not support %q targets", tt)
		}
	}
}

// analyze runs a module (optionally configured) over a fixture spec file.
func analyze(t *testing.T, fixture string, opts ...Option) []engine.Finding {
	t.Helper()
	m := New(opts...)
	fs, err := m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetContainer,
		Location: filepath.Join("testdata", fixture),
	})
	if err != nil {
		t.Fatalf("Analyze(%s): %v", fixture, err)
	}
	return fs
}

func byRuleID(fs []engine.Finding) map[string][]engine.Finding {
	m := map[string][]engine.Finding{}
	for _, f := range fs {
		m[f.RuleID] = append(m[f.RuleID], f)
	}
	return m
}

// TestGoldenPrivilegedPod pins the full finding set for the insecure pod: the
// end-to-end, offline, deterministic proof that a privileged/hostPath/docker.sock
// workload is caught exactly as reviewed.
func TestGoldenPrivilegedPod(t *testing.T) {
	assertGolden(t, "privileged.pod.json", "privileged.golden.json")
}

func TestGoldenHardenedOCI(t *testing.T) {
	assertGolden(t, "hardened.oci.json", "hardened.golden.json")
}

func assertGolden(t *testing.T, fixture, goldenName string) {
	t.Helper()
	fs := analyze(t, fixture)
	data, err := json.MarshalIndent(fs, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	golden := filepath.Join("testdata", goldenName)
	if *update {
		if err := os.WriteFile(golden, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if !bytes.Equal(want, data) {
		t.Errorf("golden mismatch for %s; run `go test ./internal/modules/harden/ -run Golden -update`", fixture)
	}
}

// TestPrivilegedPodCatchesTheBigThree asserts the specific escapes the Phase-7
// definition of done calls out: privileged, hostPath, and docker.sock.
func TestPrivilegedPodCatchesTheBigThree(t *testing.T) {
	fs := byRuleID(analyze(t, "privileged.pod.json"))
	for _, id := range []string{"DS-RAT-BOX-001", "DS-RAT-BOX-010", "DS-RAT-BOX-011"} {
		if len(fs[id]) == 0 {
			t.Errorf("expected finding %s on the privileged pod", id)
		}
	}
	// docker.sock is CRITICAL.
	if fs["DS-RAT-BOX-010"][0].Severity != engine.SeverityCritical {
		t.Errorf("docker.sock should be CRITICAL, got %s", fs["DS-RAT-BOX-010"][0].Severity)
	}
	// SYS_ADMIN dangerous cap is CRITICAL and reported per-capability.
	var sawSysAdmin bool
	for _, f := range fs["DS-RAT-BOX-004"] {
		if f.Resource == "legacy-agent/app:CAP_SYS_ADMIN" {
			sawSysAdmin = true
			if f.Severity != engine.SeverityCritical {
				t.Errorf("CAP_SYS_ADMIN should be CRITICAL, got %s", f.Severity)
			}
		}
	}
	if !sawSysAdmin {
		t.Errorf("expected a per-capability DS-RAT-BOX-004 finding for CAP_SYS_ADMIN")
	}
	// Every finding must carry a rule id, a remediation, and standard references.
	for _, f := range analyze(t, "privileged.pod.json") {
		if f.RuleID == "" || f.Remediation == "" || len(f.References) == 0 {
			t.Errorf("finding %s missing rule id / remediation / references", f.RuleID)
		}
	}
}

func TestHardenedOCIIsClean(t *testing.T) {
	for _, f := range analyze(t, "hardened.oci.json") {
		if f.Severity == engine.SeverityHigh || f.Severity == engine.SeverityCritical {
			t.Errorf("hardened OCI should not emit high/critical findings: %s %q", f.RuleID, f.Title)
		}
	}
}

// TestGPUFlagged exercises the AI-workload GPU isolation checks.
func TestGPUFlagged(t *testing.T) {
	fs := byRuleID(analyze(t, "gpu.pod.json"))
	if len(fs["DS-RAT-BOX-017"]) == 0 {
		t.Errorf("expected GPU exposure finding DS-RAT-BOX-017 (NVIDIA_VISIBLE_DEVICES=all)")
	}
	if fs["DS-RAT-BOX-017"][0].Severity != engine.SeverityMedium {
		t.Errorf("NVIDIA_VISIBLE_DEVICES=all should be MEDIUM, got %s", fs["DS-RAT-BOX-017"][0].Severity)
	}
	if len(fs["DS-RAT-BOX-018"]) == 0 {
		t.Errorf("expected multi-tenant GPU sharing finding DS-RAT-BOX-018")
	}
}

// TestBundleOffByDefault proves the AI-age feature is opt-in: the DS-RAT-BOX-900
// bundle appears only when the module is configured with WithHardeningBundle.
func TestBundleOffByDefault(t *testing.T) {
	if len(byRuleID(analyze(t, "privileged.pod.json"))["DS-RAT-BOX-900"]) != 0 {
		t.Errorf("hardening bundle must be OFF by default")
	}
	withBundle := byRuleID(analyze(t, "privileged.pod.json", WithHardeningBundle()))
	if len(withBundle["DS-RAT-BOX-900"]) == 0 {
		t.Fatalf("hardening bundle should appear when enabled")
	}
	// The bundle finding carries an applyable, parseable bundle.
	b := withBundle["DS-RAT-BOX-900"][0]
	raw, ok := b.Metadata["bundle"]
	if !ok {
		t.Fatal("bundle finding missing Metadata[\"bundle\"]")
	}
	var parsed struct {
		DryRun          bool           `json:"dry_run"`
		SecurityContext map[string]any `json:"security_context"`
		Addressed       []string       `json:"addressed"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatalf("bundle JSON not parseable: %v", err)
	}
	if !parsed.DryRun {
		t.Errorf("Analyze bundle must be a dry-run plan")
	}
	if parsed.SecurityContext["privileged"] != false {
		t.Errorf("bundle should de-privilege the workload")
	}
	if len(parsed.Addressed) == 0 {
		t.Errorf("bundle should address at least one control")
	}
}

func TestDeterministic(t *testing.T) {
	first, err := json.Marshal(analyze(t, "privileged.pod.json"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, _ := json.Marshal(analyze(t, "privileged.pod.json"))
		if !bytes.Equal(first, again) {
			t.Fatalf("non-deterministic module output on run %d", i)
		}
	}
}

func TestUnknownInputIsQuiet(t *testing.T) {
	m := New()
	fs, err := m.Analyze(context.Background(), &engine.Target{
		Type:    engine.TargetContainer,
		Content: []byte(`{"unrelated":"json"}`),
	})
	if err != nil {
		t.Fatalf("unknown JSON should not error, got %v", err)
	}
	if fs != nil {
		t.Errorf("unknown JSON should yield no findings, got %v", fs)
	}
}

func TestMalformedInputErrors(t *testing.T) {
	m := New()
	_, err := m.Analyze(context.Background(), &engine.Target{
		Type:    engine.TargetContainer,
		Content: []byte(`{not json`),
	})
	if err == nil {
		t.Errorf("malformed JSON should surface an error")
	}
}
