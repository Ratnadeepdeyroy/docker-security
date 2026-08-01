package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withMutedStdio runs fn with stdout/stderr redirected to /dev/null so command
// output does not pollute test logs; only the returned exit code is asserted.
func withMutedStdio(t *testing.T, fn func() int) int {
	t.Helper()
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open devnull: %v", err)
	}
	defer devnull.Close()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = devnull, devnull
	defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
	return fn()
}

func TestDispatchExitCodes(t *testing.T) {
	fixture := filepath.Join("testdata", "mini.json")
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no args → usage", nil, 2},
		{"unknown command", []string{"bogus"}, 2},
		{"version", []string{"version"}, 0},
		{"rules text", []string{"rules"}, 0},
		{"rules json", []string{"rules", "--format", "json"}, 0},
		{"help", []string{"help"}, 0},
		{"replay detections found", []string{"replay", fixture}, 1},
		{"replay flags-first", []string{"replay", "--format", "json", fixture}, 1},
		{"replay missing file", []string{"replay", "nope.json"}, 2},
		{"replay enforce without ack", []string{"replay", fixture, "--mode", "enforce"}, 3},
		{"replay bad mode", []string{"replay", fixture, "--mode", "bogus"}, 2},
		{"replay anomaly without baseline", []string{"replay", fixture, "--enable-anomaly"}, 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := withMutedStdio(t, func() int { return run(tc.args) })
			if got != tc.want {
				t.Errorf("run(%v) = %d, want %d", tc.args, got, tc.want)
			}
		})
	}
}

func TestRunLiveUnsupportedOnThisPlatform(t *testing.T) {
	// On darwin (CI), /proc live capture is unsupported → exit 3 with guidance.
	code := withMutedStdio(t, func() int { return run([]string{"run"}) })
	if code != 3 {
		t.Fatalf("run exit=%d, want 3 on unsupported platform", code)
	}
}

func TestReplayEnforceWithAckSucceeds(t *testing.T) {
	fixture := filepath.Join("testdata", "mini.json")
	// Enforce + ack is accepted; a detection is present so the code is 1.
	got := withMutedStdio(t, func() int {
		return run([]string{"replay", fixture, "--mode", "enforce", "--i-acknowledge"})
	})
	if got != 1 {
		t.Errorf("armed enforce over a detection stream = %d, want 1", got)
	}
}

func TestLearnProfileWritesFiles(t *testing.T) {
	fixture := filepath.Join("testdata", "mini.json")
	out := t.TempDir()
	got := withMutedStdio(t, func() int {
		return run([]string{"replay", fixture, "--learn-profile", "--profile-out", out})
	})
	if got != 0 {
		t.Fatalf("learn-profile exit = %d, want 0", got)
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("expected a generated seccomp profile file")
	}
}

func TestReplayForensicsWritesBundles(t *testing.T) {
	// Use the richer core fixture via an inline copy is unnecessary; the mini
	// fixture fires DS-RAT-RT-001, which is enough to produce one bundle.
	fixture := filepath.Join("testdata", "mini.json")
	dir := t.TempDir()
	got := withMutedStdio(t, func() int {
		return run([]string{"replay", fixture, "--forensics-dir", dir})
	})
	if got != 1 {
		t.Fatalf("replay exit = %d, want 1", got)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) == 0 {
		t.Error("expected at least one forensic bundle written")
	}
}

func TestReplayEnforceModePlansKill(t *testing.T) {
	out := filepath.Join(t.TempDir(), "a.jsonl")
	code := withMutedStdio(t, func() int {
		return run([]string{"replay", "--mode", "enforce", "--i-acknowledge", "--alert-file", out, "testdata/mini.json"})
	})
	if code != 1 {
		t.Fatalf("exit=%d want 1", code)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read alert file: %v", err)
	}
	if !strings.Contains(string(b), `"kind":"kill"`) {
		t.Fatalf("expected a kill action in alert output, got:\n%s", b)
	}
}

func TestReplayDetectModeDoesNotPlanKill(t *testing.T) {
	out := filepath.Join(t.TempDir(), "a.jsonl")
	code := withMutedStdio(t, func() int {
		return run([]string{"replay", "--alert-file", out, "testdata/mini.json"})
	})
	if code != 1 {
		t.Fatalf("exit=%d want 1", code)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read alert file: %v", err)
	}
	if strings.Contains(string(b), `"kind":"kill"`) {
		t.Fatalf("detect mode must not plan a kill action, got:\n%s", b)
	}
	if !strings.Contains(string(b), `"kind":"alert"`) {
		t.Fatalf("expected an alert action in detect mode, got:\n%s", b)
	}
}

func TestReplayExceptionsSuppressDetection(t *testing.T) {
	// mini.json's sole detection is DS-RAT-RT-001; suppressing that rule id
	// leaves zero records, so exit drops to 0.
	exc := filepath.Join(t.TempDir(), "exc.json")
	if err := os.WriteFile(exc, []byte(`{"exceptions":[{"rule_id":"DS-RAT-RT-001"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	code := run([]string{"replay", "--exceptions", exc, "testdata/mini.json"})
	if code != 0 {
		t.Fatalf("exit=%d want 0 (the only detection was suppressed)", code)
	}
}

func TestReplayWritesAlertFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "a.jsonl")
	code := run([]string{"replay", "--alert-file", out, "testdata/mini.json"})
	if code != 1 { // mini.json produces detections
		t.Fatalf("exit=%d want 1", code)
	}
	b, err := os.ReadFile(out)
	if err != nil || len(b) == 0 {
		t.Fatalf("alert file empty: err=%v", err)
	}
}
