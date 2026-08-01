package kubebench

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/compliance"
	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

var update = flag.Bool("update", false, "update golden files")

func loadFixture(t *testing.T, name string) *Evidence {
	t.Helper()
	ev, err := Load(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("Load(%s): %v", name, err)
	}
	return ev
}

func statusByID(rep *compliance.Report) map[string]compliance.Status {
	m := map[string]compliance.Status{}
	for _, r := range rep.Results {
		m[r.Control.ID] = r.Status
	}
	return m
}

func TestSelfManagedFailsExpectedControls(t *testing.T) {
	rep := Assess(loadFixture(t, "selfmanaged"))
	got := statusByID(rep)

	wantFail := map[string]string{
		"1.1.1":  "apiserver manifest world-writable",
		"1.2.1":  "anonymous-auth true",
		"1.2.6":  "authorization-mode AlwaysAllow",
		"1.2.8":  "RBAC not in authz mode",
		"1.2.22": "no audit log",
		"2.3":    "etcd auto-tls",
		"4.2.1":  "kubelet anon auth",
		"4.2.4":  "kubelet read-only port",
		"5.1.1":  "extra cluster-admin binding",
		"5.1.3":  "wildcard role",
		"5.2.2":  "PSA disabled",
		"5.3.2":  "no network policies",
		"5.7.4":  "default namespace used",
	}
	for id, why := range wantFail {
		if got[id] != compliance.StatusFail {
			t.Errorf("control %s (%s): got %s, want FAIL", id, why, got[id])
		}
	}
	if s := rep.Score(); s > 40 {
		t.Errorf("insecure self-managed cluster scored %d%%, expected low", s)
	}
	if rep.Version != "1.9.0" {
		t.Errorf("k8s 1.29 should map to benchmark v1.9.0, got %s", rep.Version)
	}
}

func TestManagedProfileSkipsProviderControls(t *testing.T) {
	rep := Assess(loadFixture(t, "eks"))
	if rep.Profile != "eks" {
		t.Fatalf("profile = %q, want eks", rep.Profile)
	}
	got := statusByID(rep)

	// Control-plane and etcd controls are provider-owned on EKS: reported INFO,
	// never scored PASS/FAIL.
	for _, id := range []string{"1.2.1", "1.2.6", "2.1", "2.2"} {
		if got[id] != compliance.StatusInfo {
			t.Errorf("managed control %s should be INFO (provider-owned), got %s", id, got[id])
		}
	}
	// Customer-owned node + policy controls are scored and pass on this fixture.
	for _, id := range []string{"4.2.1", "4.2.4", "5.1.1", "5.2.2", "5.3.2"} {
		if got[id] != compliance.StatusPass {
			t.Errorf("customer control %s should PASS on hardened EKS, got %s", id, got[id])
		}
	}
	// k8s 1.28 → benchmark v1.9.0.
	if rep.Version != "1.9.0" {
		t.Errorf("k8s 1.28 should map to benchmark v1.9.0, got %s", rep.Version)
	}
	for _, r := range rep.Results {
		if r.Status == compliance.StatusFail {
			t.Errorf("hardened EKS unexpectedly FAILs %s: %s", r.Control.ID, r.Evidence)
		}
	}
}

func TestEveryControlCitesANonCISFramework(t *testing.T) {
	for _, c := range Benchmark(selectProfile(&Evidence{})).Controls {
		refs := c.References("CIS Kubernetes Benchmark")
		if len(refs) < 2 {
			t.Errorf("control %s cites no non-CIS framework: %v", c.ID, refs)
		}
	}
}

func TestDeterministicOutput(t *testing.T) {
	ev := loadFixture(t, "selfmanaged")
	first, err := json.Marshal(Assess(ev))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := json.Marshal(Assess(ev))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("non-deterministic output on run %d", i)
		}
	}
}

func TestGoldenReports(t *testing.T) {
	for _, name := range []string{"selfmanaged", "eks"} {
		t.Run(name, func(t *testing.T) {
			rep := Assess(loadFixture(t, name))
			data, err := json.MarshalIndent(rep, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			data = append(data, '\n')
			golden := filepath.Join("testdata", name, "report.golden.json")
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
				t.Errorf("golden mismatch for %s; run `go test -run Golden -update`", name)
			}
		})
	}
}

func TestNarrativeOffByDefault(t *testing.T) {
	m := New()
	target := &engine.Target{Type: engine.TargetFilesystem, Location: filepath.Join("testdata", "selfmanaged")}

	fs, err := m.Analyze(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if findByRule(fs, "DS-RAT-CIS-NARRATIVE") != nil {
		t.Errorf("narrative present without opt-in; must be off by default")
	}
	if findByRule(fs, "DS-RAT-CIS-SUMMARY") == nil {
		t.Errorf("expected a DS-RAT-CIS-SUMMARY finding")
	}

	target.Metadata = map[string]string{"compliance.narrative": "true", "compliance.now": "2026-07-04T00:00:00Z"}
	withNar, err := m.Analyze(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if findByRule(withNar, "DS-RAT-CIS-NARRATIVE") == nil {
		t.Fatalf("narrative missing after opt-in")
	}
}

func TestDriftReportsRegressionAndFix(t *testing.T) {
	// Baseline: hardened EKS. Current: same but with one regressed control.
	baseline := Assess(loadFixture(t, "eks"))
	current := Assess(loadFixture(t, "eks"))
	// Flip a passing control to FAIL to simulate drift.
	for i := range current.Results {
		if current.Results[i].Control.ID == "4.2.4" {
			current.Results[i].Status = compliance.StatusFail
		}
	}
	d := compliance.Diff(baseline, current)
	if len(d.Regressed) != 1 || d.Regressed[0].ControlID != "4.2.4" {
		t.Errorf("expected 4.2.4 to regress, got %+v", d.Regressed)
	}
	if !d.HasDrift() {
		t.Errorf("expected drift to be detected")
	}
}

func TestHostileInput(t *testing.T) {
	ev, err := Load(filepath.Join("testdata", "nope"))
	if err != nil {
		t.Fatalf("missing path should not error, got %v", err)
	}
	if len(ev.Notes) == 0 {
		t.Errorf("expected a note for a missing path")
	}
	bad := filepath.Join(t.TempDir(), "evidence.json")
	if err := os.WriteFile(bad, []byte("{bad"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil {
		t.Errorf("malformed evidence should error")
	}
}

func findByRule(fs []engine.Finding, rule string) *engine.Finding {
	for i := range fs {
		if fs[i].RuleID == rule {
			return &fs[i]
		}
	}
	return nil
}
