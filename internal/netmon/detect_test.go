package netmon

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// update rewrites the golden files instead of comparing. Run:
//
//	go test ./internal/netmon/ -run Golden -update
//
// then eyeball the diff — the golden is a hand-verified baseline, not whatever
// the code happened to emit.
var update = flag.Bool("update", false, "rewrite golden files")

// kinds indexes anomalies by kind for assertions.
func kinds(as []Anomaly) map[AnomalyKind][]Anomaly {
	m := map[AnomalyKind][]Anomaly{}
	for _, a := range as {
		m[a.Kind] = append(m[a.Kind], a)
	}
	return m
}

// TestDetectorFiresExpectedHeuristics is the behavioural proof: each recorded
// threat in the fixture must trip its detector at the right severity, and the
// AI-age heuristics must stay silent under default options.
func TestDetectorFiresExpectedHeuristics(t *testing.T) {
	c := loadFixture(t, "capture_threats.json")
	rep := Analyze(c, Options{}) // default options: AI features OFF
	got := kinds(rep.Anomalies)

	want := []struct {
		kind AnomalyKind
		sev  engine.Severity
		wl   string
	}{
		{KindIMDS, engine.SeverityCritical, "prod/malware"},
		{KindBeacon, engine.SeverityHigh, "prod/malware"},
		{KindExfil, engine.SeverityHigh, "prod/malware"},
		{KindLateral, engine.SeverityHigh, "prod/scanner"},
		{KindDNSTunnel, engine.SeverityHigh, "prod/dns-tunnel"},
		{KindDGA, engine.SeverityHigh, "prod/dga-bot"},
		{KindHostNetwork, engine.SeverityMedium, "infra/host-net-app"},
		{KindBlockedEg, engine.SeverityLow, "prod/blocked-app"},
	}
	for _, w := range want {
		hits := got[w.kind]
		if len(hits) == 0 {
			t.Errorf("expected anomaly kind %q to fire, but it did not", w.kind)
			continue
		}
		var matched bool
		for _, a := range hits {
			if a.Workload == w.wl {
				matched = true
				if a.Severity != w.sev {
					t.Errorf("%s on %s: severity=%s want %s", w.kind, w.wl, a.Severity, w.sev)
				}
			}
		}
		if !matched {
			t.Errorf("anomaly %q did not fire on expected workload %q", w.kind, w.wl)
		}
	}

	// AI-age features are OFF by default: they must not appear.
	if len(got[KindAgentEgress]) != 0 {
		t.Errorf("agent-egress governance must be off by default, got %d", len(got[KindAgentEgress]))
	}
	if len(got[KindAnomalousEg]) != 0 {
		t.Errorf("egress intent modelling must be off by default, got %d", len(got[KindAnomalousEg]))
	}
}

// TestBeaconRequiresRegularity guards against the beacon detector firing on
// bursty traffic: the blocked-app's irregular denials must not read as a beacon.
func TestBeaconRequiresRegularity(t *testing.T) {
	c := loadFixture(t, "capture_threats.json")
	rep := Analyze(c, Options{})
	for _, a := range rep.Anomalies {
		if a.Kind == KindBeacon && a.Workload == "prod/blocked-app" {
			t.Error("beacon fired on irregular (bursty) traffic — CV gate is not working")
		}
	}
}

// TestDeterministic proves re-running yields identical anomalies — the property
// the golden and the whole engine depend on.
func TestDeterministic(t *testing.T) {
	c1 := loadFixture(t, "capture_threats.json")
	c2 := loadFixture(t, "capture_threats.json")
	if !reflect.DeepEqual(Analyze(c1, Options{}).Anomalies, Analyze(c2, Options{}).Anomalies) {
		t.Error("two runs over the same capture produced different anomalies")
	}
}

// TestGoldenThreats pins the full anomaly set for the threats fixture.
func TestGoldenThreats(t *testing.T) {
	c := loadFixture(t, "capture_threats.json")
	rep := Analyze(c, Options{})
	assertGolden(t, "anomalies_threats.golden.json", rep.Anomalies)
}

// assertGolden marshals v and compares it against (or rewrites) a golden file.
func assertGolden(t *testing.T, name string, v any) {
	t.Helper()
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	pretty = append(pretty, '\n')
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, pretty, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote golden %s", path)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s (run with -update first): %v", name, err)
	}
	if string(pretty) != string(want) {
		t.Errorf("%s differs from golden.\n--- got ---\n%s", name, pretty)
	}
}
