package imageaudit

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// update regenerates the golden file instead of comparing against it. Run:
//
//	go test ./internal/modules/imageaudit/ -run Golden -update
//
// then eyeball the diff before committing — the golden is a hand-verified
// baseline, not whatever the code happens to emit.
var update = flag.Bool("update", false, "rewrite golden files")

func TestSupports(t *testing.T) {
	m := New()
	if !m.Supports(engine.TargetImage) {
		t.Error("imageaudit must support image targets")
	}
	for _, tt := range []engine.TargetType{engine.TargetDockerfile, engine.TargetFilesystem, engine.TargetContainer, engine.TargetRegistry} {
		if m.Supports(tt) {
			t.Errorf("imageaudit must not support %q targets", tt)
		}
	}
}

// analyze runs the default (CIS-baseline) module over a fixture tarball.
func analyze(t *testing.T, fixture string, opts ...Option) []engine.Finding {
	t.Helper()
	m := New(opts...)
	fs, err := m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetImage,
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

// TestGoldenInsecureImage pins the full finding set for the insecure fixture.
// This is the end-to-end, offline, deterministic proof: the module loads a
// committed image via internal/oci and produces exactly the reviewed baseline.
func TestGoldenInsecureImage(t *testing.T) {
	got := analyze(t, "insecure.tar")

	goldenPath := filepath.Join("testdata", "insecure.golden.json")
	pretty, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile(goldenPath, append(pretty, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote golden %s", goldenPath)
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update first): %v", err)
	}
	// Severity marshals to a string but has no UnmarshalJSON, so we compare the
	// canonical marshaled bytes rather than round-tripping back into structs.
	if string(append(pretty, '\n')) != string(want) {
		t.Errorf("findings differ from golden.\n--- got ---\n%s\n--- want ---\n%s", pretty, want)
	}
}

// TestHostileInputIsBounded proves that a missing or malformed target yields an
// error, never a panic — the module must survive untrusted input.
func TestHostileInputIsBounded(t *testing.T) {
	m := New()
	// Nonexistent path.
	if _, err := m.Analyze(context.Background(), &engine.Target{Type: engine.TargetImage, Location: filepath.Join(t.TempDir(), "nope.tar")}); err == nil {
		t.Error("missing image should return an error")
	}
	// A file that is not a valid image archive.
	bad := filepath.Join(t.TempDir(), "garbage.tar")
	if err := os.WriteFile(bad, []byte("this is not a tar"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Analyze(context.Background(), &engine.Target{Type: engine.TargetImage, Location: bad}); err == nil {
		t.Error("garbage archive should return an error, not a panic")
	}
	// Wrong target type is rejected up front.
	if _, err := m.Analyze(context.Background(), &engine.Target{Type: engine.TargetDockerfile, Location: "x"}); err == nil {
		t.Error("non-image target should be rejected")
	}
}

// TestDeterministic proves that re-running on the same fixture yields identical
// output — the property the whole engine relies on for stable reports.
func TestDeterministic(t *testing.T) {
	first := analyze(t, "insecure.tar")
	second := analyze(t, "insecure.tar")
	if !reflect.DeepEqual(first, second) {
		t.Error("two runs over the same image produced different findings")
	}
}

// TestDistrolessScoresClean is the DoD requirement: the hardened fixture must
// raise nothing actionable. The only finding permitted is the positive INFO
// "distroless detected" reward.
func TestDistrolessScoresClean(t *testing.T) {
	got := analyze(t, "distroless.tar")
	for _, f := range got {
		if f.Severity > engine.SeverityInfo {
			t.Errorf("distroless image raised %s finding %s (%s); expected clean", f.Severity, f.RuleID, f.Title)
		}
	}
	ids := byRuleID(got)
	if _, ok := ids["DS-RAT-IMG-011"]; !ok {
		t.Errorf("expected the DS-RAT-IMG-011 distroless reward on the hardened image; got %v", ids)
	}
	if f := ids["DS-RAT-IMG-011"]; len(f) == 1 && f[0].Severity != engine.SeverityInfo {
		t.Errorf("distroless reward should be INFO, got %s", f[0].Severity)
	}
}
