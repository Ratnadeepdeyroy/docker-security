package imageaudit

import (
	"encoding/json"
	"io/fs"
	"strconv"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// findByID returns the first finding with the given rule id, or a zero Finding.
func findByID(fs []engine.Finding, id string) (engine.Finding, bool) {
	for _, f := range fs {
		if f.RuleID == id {
			return f, true
		}
	}
	return engine.Finding{}, false
}

// TestAttackSurfaceOffByDefault is the SHARED_CONTRACT §4 guarantee: the
// enrichment finding must be absent unless explicitly enabled.
func TestAttackSurfaceOffByDefault(t *testing.T) {
	if _, ok := findByID(analyze(t, "insecure.tar"), "DS-RAT-IMG-100"); ok {
		t.Error("DS-RAT-IMG-100 must not appear without WithAttackSurfaceScore()")
	}
}

func TestAttackSurfaceScoreOnInsecure(t *testing.T) {
	fs := analyze(t, "insecure.tar", WithAttackSurfaceScore())
	f, ok := findByID(fs, "DS-RAT-IMG-100")
	if !ok {
		t.Fatal("DS-RAT-IMG-100 should appear with WithAttackSurfaceScore()")
	}
	if f.Severity != engine.SeverityInfo {
		t.Errorf("score finding must be INFO (gating-neutral), got %s", f.Severity)
	}

	var plan hardeningPlan
	if err := json.Unmarshal([]byte(f.Metadata["hardening_plan"]), &plan); err != nil {
		t.Fatalf("hardening_plan is not valid JSON: %v", err)
	}
	if plan.Grade != "F" {
		t.Errorf("a maximally-bad image should grade F, got %q (score %d)", plan.Grade, plan.Score)
	}
	if plan.Distroless {
		t.Error("insecure image is not distroless")
	}
	if len(plan.Steps) == 0 {
		t.Error("an insecure image must produce agent-appliable hardening steps")
	}
	// The plan must name the big levers.
	names := map[string]bool{}
	for _, fac := range plan.Factors {
		names[fac.Name] = true
	}
	for _, want := range []string{"runs_as_root", "shell_present", "package_manager_present", "setuid_binaries", "secret_in_env", "exposed_port"} {
		if !names[want] {
			t.Errorf("expected surface factor %q in plan, got %v", want, names)
		}
	}
	if f.Metadata["setuid_count"] != "2" {
		t.Errorf("metadata setuid_count = %q, want 2", f.Metadata["setuid_count"])
	}
}

func TestAttackSurfaceScoreOnDistroless(t *testing.T) {
	fs := analyze(t, "distroless.tar", WithAttackSurfaceScore())
	f, ok := findByID(fs, "DS-RAT-IMG-100")
	if !ok {
		t.Fatal("DS-RAT-IMG-100 should appear with WithAttackSurfaceScore()")
	}
	var plan hardeningPlan
	if err := json.Unmarshal([]byte(f.Metadata["hardening_plan"]), &plan); err != nil {
		t.Fatalf("hardening_plan JSON: %v", err)
	}
	if !plan.Distroless {
		t.Error("hardened fixture should be flagged distroless")
	}
	if plan.Grade != "A" {
		t.Errorf("hardened image should grade A, got %q (score %d)", plan.Grade, plan.Score)
	}
	if plan.Score > 10 {
		t.Errorf("hardened image score should be minimal, got %d", plan.Score)
	}
}

// TestBuildPlanDeterministic ensures the pure scorer yields identical output
// across runs (no map-iteration or clock leakage).
func TestBuildPlanDeterministic(t *testing.T) {
	ac := ctxWith(
		containerConfig{
			User:         "root",
			ExposedPorts: map[string]empty{"22/tcp": {}, "80/tcp": {}},
			Env:          []string{"DB_PASSWORD=x"},
		},
		nil,
		nil, nil,
	)
	a, _ := json.Marshal(buildPlan(ac))
	b, _ := json.Marshal(buildPlan(ac))
	if string(a) != string(b) {
		t.Error("buildPlan is not deterministic")
	}
}

// TestScoreCappedAt100 guards the additive score from overflowing its stated
// 0..100 range on a pathological image (root + shell + pkg mgr + many setuid +
// secret env + SSH/privileged ports).
func TestScoreCappedAt100(t *testing.T) {
	files := []*oci.File{
		{Path: "bin/sh", Mode: 0o755},
		{Path: "usr/bin/apt-get", Mode: 0o755},
	}
	for i := 0; i < 50; i++ {
		files = append(files, &oci.File{Path: "usr/bin/tool" + strconv.Itoa(i), Mode: fs.FileMode(0o4755)})
	}
	ac := ctxWith(
		containerConfig{
			User:         "root",
			ExposedPorts: map[string]empty{"22/tcp": {}, "80/tcp": {}, "81/tcp": {}, "82/tcp": {}},
			Env:          []string{"SECRET=x"},
		},
		nil, files, nil,
	)
	if p := buildPlan(ac); p.Score != 100 {
		t.Errorf("score should cap at 100, got %d", p.Score)
	}
}
