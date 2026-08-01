package dockerbench

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

// update regenerates golden files: `go test ./internal/modules/dockerbench -update`.
var update = flag.Bool("update", false, "update golden files")

// loadFixture loads the evidence snapshot for a named testdata dir.
func loadFixture(t *testing.T, name string) *Evidence {
	t.Helper()
	ev, err := Load(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("Load(%s): %v", name, err)
	}
	return ev
}

// statusByID indexes a report's results by control id for assertions. The
// fixtures carry no waivers, so raw Status equals effective status here.
func statusByID(rep *compliance.Report) map[string]compliance.Status {
	m := map[string]compliance.Status{}
	for _, r := range rep.Results {
		m[r.Control.ID] = r.Status
	}
	return m
}

// controlIDLess is a numeric-aware "less" for dotted control ids, used to assert
// the report is sorted (2.2 before 2.10, not lexicographically).
func controlIDLess(a, b string) bool {
	as, bs := splitDots(a), splitDots(b)
	for i := 0; i < len(as) && i < len(bs); i++ {
		if as[i] != bs[i] {
			return as[i] < bs[i]
		}
	}
	return len(as) < len(bs)
}

func splitDots(s string) []int {
	var out []int
	n, cur := 0, false
	for _, r := range s {
		if r == '.' {
			out = append(out, n)
			n, cur = 0, false
			continue
		}
		if r >= '0' && r <= '9' {
			n = n*10 + int(r-'0')
			cur = true
		}
	}
	if cur {
		out = append(out, n)
	}
	return out
}

func TestInsecureHostFailsExpectedControls(t *testing.T) {
	rep := Assess(loadFixture(t, "insecure"))
	got := statusByID(rep)

	// A representative failure per section proves the checks actually fire.
	wantFail := map[string]string{
		"2.3":  "iptables disabled",
		"2.4":  "insecure registries",
		"2.5":  "aufs storage driver",
		"2.6":  "tcp socket without TLS",
		"2.16": "experimental enabled",
		"3.6":  "/etc/docker world-writable",
		"3.17": "daemon.json wrong owner",
		"5.4":  "privileged container",
		"5.9":  "host network",
		"5.31": "docker socket mounted",
	}
	for id, why := range wantFail {
		if got[id] != compliance.StatusFail {
			t.Errorf("control %s (%s): got %s, want FAIL", id, why, got[id])
		}
	}
	if s := rep.Score(); s > 40 {
		t.Errorf("insecure host scored %d%%, expected a low score", s)
	}
}

func TestHardenedHostMostlyPasses(t *testing.T) {
	rep := Assess(loadFixture(t, "hardened"))
	got := statusByID(rep)

	// No scored control should FAIL on the hardened fixture.
	for _, r := range rep.Results {
		if r.Status == compliance.StatusFail {
			t.Errorf("hardened host unexpectedly FAILs %s: %s", r.Control.ID, r.Evidence)
		}
	}
	// Spot-check that hardening was actually recognized, not just absent.
	for _, id := range []string{"2.1", "2.13", "3.16", "5.4", "5.12", "5.26"} {
		if got[id] != compliance.StatusPass {
			t.Errorf("control %s: got %s, want PASS on hardened host", id, got[id])
		}
	}
	if s := rep.Score(); s < 90 {
		t.Errorf("hardened host scored %d%%, expected >= 90%%", s)
	}
}

func TestEveryControlCitesANonCISFramework(t *testing.T) {
	// Definition of Done: every control cites CIS + at least one more framework.
	for _, c := range Benchmark().Controls {
		refs := c.References("CIS Docker Benchmark")
		if len(refs) < 2 {
			t.Errorf("control %s cites no non-CIS framework: %v", c.ID, refs)
		}
	}
}

func TestDeterministicOrderingAndOutput(t *testing.T) {
	ev := loadFixture(t, "insecure")
	first, err := json.Marshal(Assess(ev))
	if err != nil {
		t.Fatal(err)
	}
	// Re-running on identical evidence must be byte-identical.
	for i := 0; i < 5; i++ {
		again, err := json.Marshal(Assess(ev))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatalf("non-deterministic output on run %d", i)
		}
	}
	// Results must be in ascending numeric control order (2.2 before 2.10 etc).
	rep := Assess(ev)
	for i := 1; i < len(rep.Results); i++ {
		if !controlIDLess(rep.Results[i-1].Control.ID, rep.Results[i].Control.ID) {
			t.Errorf("results not sorted: %s before %s",
				rep.Results[i-1].Control.ID, rep.Results[i].Control.ID)
		}
	}
}

func TestGoldenReports(t *testing.T) {
	for _, name := range []string{"insecure", "hardened"} {
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
	target := &engine.Target{Type: engine.TargetFilesystem, Location: filepath.Join("testdata", "insecure")}

	// Default: no narrative finding.
	fs, err := m.Analyze(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if findByRule(fs, "DS-RAT-CIS-NARRATIVE") != nil {
		t.Errorf("narrative present without opt-in; it must be off by default")
	}
	if findByRule(fs, "DS-RAT-CIS-SUMMARY") == nil {
		t.Errorf("expected a DS-RAT-CIS-SUMMARY finding")
	}

	// Opt in via metadata with an injected clock ⇒ present and deterministic.
	target.Metadata = map[string]string{
		"compliance.narrative": "true",
		"compliance.now":       "2026-07-04T00:00:00Z",
	}
	withNar, err := m.Analyze(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	nar := findByRule(withNar, "DS-RAT-CIS-NARRATIVE")
	if nar == nil {
		t.Fatalf("narrative missing after opt-in")
	}
	if nar.Description == "" {
		t.Errorf("narrative finding has empty body")
	}
}

func TestHostileInput(t *testing.T) {
	// Missing path degrades to INFO, never errors or crashes.
	ev, err := Load(filepath.Join("testdata", "does-not-exist"))
	if err != nil {
		t.Fatalf("missing path should not error, got %v", err)
	}
	if len(ev.Notes) == 0 {
		t.Errorf("expected a collection note for a missing path")
	}
	// Malformed JSON is a clear error, not a panic.
	bad := filepath.Join(t.TempDir(), "evidence.json")
	if err := os.WriteFile(bad, []byte("{not valid json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(bad); err == nil {
		t.Errorf("malformed evidence should return an error")
	}
}

// findByRule returns the first finding with the given rule id, or nil.
func findByRule(fs []engine.Finding, rule string) *engine.Finding {
	for i := range fs {
		if fs[i].RuleID == rule {
			return &fs[i]
		}
	}
	return nil
}
