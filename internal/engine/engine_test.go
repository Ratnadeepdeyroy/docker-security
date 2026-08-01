package engine

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// fakeModule is a controllable Module for exercising the engine.
type fakeModule struct {
	name     string
	supports TargetType
	findings []Finding
	err      error
	panicVal any // if non-nil, Analyze panics with this value instead of returning
	ran      bool
}

func (m *fakeModule) Name() string               { return m.name }
func (m *fakeModule) Description() string        { return "fake " + m.name }
func (m *fakeModule) Domains() []string          { return []string{"0"} }
func (m *fakeModule) Supports(t TargetType) bool { return t == m.supports }
func (m *fakeModule) Analyze(context.Context, *Target) ([]Finding, error) {
	m.ran = true
	if m.panicVal != nil {
		panic(m.panicVal)
	}
	return m.findings, m.err
}

func TestRegistryPreservesFirstSeenOrder(t *testing.T) {
	r := NewRegistry()
	r.Register(&fakeModule{name: "a"})
	r.Register(&fakeModule{name: "b"})
	r.Register(&fakeModule{name: "a"}) // re-register must not reorder
	if got := r.Names(); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("order = %v, want [a b]", got)
	}
}

func TestRunFiltersBySupportsAndRecordsRuns(t *testing.T) {
	img := &fakeModule{name: "img", supports: TargetImage, findings: []Finding{{RuleID: "X", Severity: SeverityHigh}}}
	df := &fakeModule{name: "df", supports: TargetDockerfile}
	r := NewRegistry()
	r.Register(img)
	r.Register(df)

	rep := New(r).Run(context.Background(), &Target{Type: TargetImage})
	if !img.ran {
		t.Error("image module should have run on an image target")
	}
	if df.ran {
		t.Error("dockerfile module must not run on an image target")
	}
	if len(rep.Findings) != 1 || rep.Findings[0].RuleID != "X" {
		t.Errorf("findings = %+v, want one X", rep.Findings)
	}
	if len(rep.ModuleRuns) != 1 || rep.ModuleRuns[0].Module != "img" {
		t.Errorf("module runs = %+v, want [img]", rep.ModuleRuns)
	}
}

func TestRunRecordsModuleErrorWithoutAborting(t *testing.T) {
	bad := &fakeModule{name: "bad", supports: TargetImage, err: context.DeadlineExceeded}
	good := &fakeModule{name: "good", supports: TargetImage, findings: []Finding{{RuleID: "OK", Severity: SeverityLow}}}
	r := NewRegistry()
	r.Register(bad)
	r.Register(good)

	rep := New(r).Run(context.Background(), &Target{Type: TargetImage})
	if !good.ran {
		t.Error("a failing module must not abort later modules")
	}
	var badRun *ModuleRun
	for i := range rep.ModuleRuns {
		if rep.ModuleRuns[i].Module == "bad" {
			badRun = &rep.ModuleRuns[i]
		}
	}
	if badRun == nil || badRun.Error == "" {
		t.Errorf("expected a recorded error for the failing module, got %+v", rep.ModuleRuns)
	}
}

// TestRunIsolatesPanickingModule is a regression test: a module panicking on
// hostile/malformed input (e.g. the Dockerfile module's ruleUserRoot on a
// bare "USER" line) must not crash the whole scan. Its panic is recorded as
// that module's ModuleRun.Error, the other modules still run, and Run
// returns normally instead of propagating the panic.
func TestRunIsolatesPanickingModule(t *testing.T) {
	bad := &fakeModule{name: "bad", supports: TargetImage, panicVal: "boom"}
	good := &fakeModule{name: "good", supports: TargetImage, findings: []Finding{{RuleID: "OK", Severity: SeverityLow}}}
	r := NewRegistry()
	r.Register(bad)
	r.Register(good)

	rep := New(r).Run(context.Background(), &Target{Type: TargetImage})

	if !bad.ran {
		t.Error("panicking module should still have been invoked")
	}
	if !good.ran {
		t.Error("a panicking module must not prevent later modules from running")
	}
	var badRun *ModuleRun
	for i := range rep.ModuleRuns {
		if rep.ModuleRuns[i].Module == "bad" {
			badRun = &rep.ModuleRuns[i]
		}
	}
	if badRun == nil || badRun.Error == "" {
		t.Fatalf("expected a recorded panic error for the failing module, got %+v", rep.ModuleRuns)
	}
	if !strings.Contains(badRun.Error, "boom") {
		t.Errorf("recorded error = %q, want it to mention the panic value", badRun.Error)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].RuleID != "OK" {
		t.Errorf("findings = %+v, want the good module's finding to survive", rep.Findings)
	}
}

// TestRunStopsOnCancelledContext is a regression test: once the context is
// cancelled, the module loop must stop cleanly instead of running the
// remaining modules as if nothing happened - a cancelled huge scan must not
// masquerade as a complete one.
func TestRunStopsOnCancelledContext(t *testing.T) {
	first := &fakeModule{name: "first", supports: TargetImage, findings: []Finding{{RuleID: "A", Severity: SeverityLow}}}
	second := &fakeModule{name: "second", supports: TargetImage, findings: []Finding{{RuleID: "B", Severity: SeverityLow}}}
	r := NewRegistry()
	r.Register(first)
	r.Register(second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled before Run starts

	rep := New(r).Run(ctx, &Target{Type: TargetImage})

	if first.ran || second.ran {
		t.Errorf("no module should run once the context is already cancelled, first.ran=%v second.ran=%v", first.ran, second.ran)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("findings = %+v, want none from a cancelled run", rep.Findings)
	}
	if len(rep.ModuleRuns) != 2 {
		t.Fatalf("expected both modules to be recorded as not-run, got %+v", rep.ModuleRuns)
	}
	for _, run := range rep.ModuleRuns {
		if run.Error == "" {
			t.Errorf("module %s should have a recorded not-run error", run.Module)
		}
	}
}

func TestRunSortsBySeverityDescending(t *testing.T) {
	m := &fakeModule{name: "m", supports: TargetImage, findings: []Finding{
		{RuleID: "low", Severity: SeverityLow},
		{RuleID: "crit", Severity: SeverityCritical},
		{RuleID: "med", Severity: SeverityMedium},
	}}
	r := NewRegistry()
	r.Register(m)
	rep := New(r).Run(context.Background(), &Target{Type: TargetImage})
	if rep.Findings[0].Severity != SeverityCritical || rep.Findings[len(rep.Findings)-1].Severity != SeverityLow {
		t.Errorf("not sorted by severity desc: %+v", rep.Findings)
	}
}

func TestReportGating(t *testing.T) {
	rep := &Report{Findings: []Finding{{Severity: SeverityMedium}, {Severity: SeverityHigh}}}
	if rep.Highest() != SeverityHigh {
		t.Errorf("Highest = %v, want HIGH", rep.Highest())
	}
	if !rep.FailsAt(SeverityHigh) {
		t.Error("FailsAt(HIGH) should be true (a HIGH finding exists)")
	}
	if rep.FailsAt(SeverityCritical) {
		t.Error("FailsAt(CRITICAL) should be false (no CRITICAL finding)")
	}
	if rep.FailsAt(SeverityUnknown) {
		t.Error("FailsAt(UNKNOWN) disables gating and must be false")
	}
	if c := rep.Counts(); c[SeverityHigh] != 1 || c[SeverityMedium] != 1 {
		t.Errorf("counts = %v", c)
	}
}

func TestSeverityParseAndJSONRoundTrip(t *testing.T) {
	for _, name := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		s := ParseSeverity(name)
		data, err := json.Marshal(s)
		if err != nil {
			t.Fatalf("marshal %s: %v", name, err)
		}
		var back Severity
		if err := json.Unmarshal(data, &back); err != nil {
			t.Fatalf("unmarshal %s: %v", name, err)
		}
		if back != s {
			t.Errorf("round-trip %s: got %v", name, back)
		}
	}
	if ParseSeverity("nonsense") != SeverityUnknown {
		t.Error("unrecognized severity should parse to Unknown")
	}
}

func TestDetectType(t *testing.T) {
	cases := map[string]TargetType{
		"Dockerfile":      TargetDockerfile,
		"Dockerfile.prod": TargetDockerfile,
		"app.dockerfile":  TargetDockerfile,
		"alpine:3.19":     TargetImage, // not a path on disk
		"registry.io/x:1": TargetImage,
	}
	for ref, want := range cases {
		if got := DetectType(ref); got != want {
			t.Errorf("DetectType(%q) = %q, want %q", ref, got, want)
		}
	}
}
