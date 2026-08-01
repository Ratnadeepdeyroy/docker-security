package watch

import (
	"context"
	"testing"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/connector"
	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

func fnd(mod, rule, resource string, sev engine.Severity) engine.Finding {
	return engine.Finding{Module: mod, RuleID: rule, Resource: resource, Severity: sev, Title: rule}
}

func report(fs ...engine.Finding) *engine.Report {
	return &engine.Report{Tool: "dsecrat", Findings: fs, GeneratedAt: time.Unix(0, 0).UTC()}
}

func TestDiffFirstRunAllNew(t *testing.T) {
	cur := report(fnd("vuln", "CVE-1", "pkg-a", engine.SeverityHigh))
	d := Diff(nil, cur)
	if len(d.New) != 1 || len(d.Cleared) != 0 {
		t.Fatalf("first run: got New=%d Cleared=%d, want 1/0", len(d.New), len(d.Cleared))
	}
	if !d.Changed() {
		t.Errorf("first run with a finding should report Changed()")
	}
}

func TestDiffNoChange(t *testing.T) {
	a := fnd("vuln", "CVE-1", "pkg-a", engine.SeverityHigh)
	d := Diff(report(a), report(a))
	if d.Changed() {
		t.Errorf("identical reports must produce no delta, got New=%d Cleared=%d", len(d.New), len(d.Cleared))
	}
}

func TestDiffNewAndCleared(t *testing.T) {
	a := fnd("vuln", "CVE-1", "pkg-a", engine.SeverityHigh)
	b := fnd("vuln", "CVE-2", "pkg-b", engine.SeverityCritical)
	c := fnd("secrets", "SECRET-1", "layer-3", engine.SeverityMedium)

	prev := report(a, b)
	cur := report(b, c) // a cleared, c new, b unchanged
	d := Diff(prev, cur)

	if len(d.New) != 1 || d.New[0].RuleID != "SECRET-1" {
		t.Fatalf("New = %+v, want [SECRET-1]", d.New)
	}
	if len(d.Cleared) != 1 || d.Cleared[0].RuleID != "CVE-1" {
		t.Fatalf("Cleared = %+v, want [CVE-1]", d.Cleared)
	}
}

func TestDiffSortsMostSevereFirst(t *testing.T) {
	low := fnd("m", "L", "r1", engine.SeverityLow)
	crit := fnd("m", "C", "r2", engine.SeverityCritical)
	d := Diff(nil, report(low, crit))
	if d.New[0].RuleID != "C" {
		t.Errorf("New should be sorted most-severe first; got %s first", d.New[0].RuleID)
	}
}

// sameRuleDifferentResource confirms the finding key distinguishes the same rule
// firing on two different resources, so one clearing is not masked by the other.
func TestDiffDistinguishesResources(t *testing.T) {
	r1 := fnd("vuln", "CVE-1", "pkg-a", engine.SeverityHigh)
	r2 := fnd("vuln", "CVE-1", "pkg-b", engine.SeverityHigh)
	d := Diff(report(r1, r2), report(r1)) // pkg-b cleared
	if len(d.Cleared) != 1 || d.Cleared[0].Resource != "pkg-b" {
		t.Fatalf("Cleared = %+v, want [CVE-1 on pkg-b]", d.Cleared)
	}
}

// scriptedScanner returns a fixed sequence of reports, one per Scan call, so a
// watch loop is fully deterministic with no timing.
type scriptedScanner struct {
	reports []*engine.Report
	i       int
}

func (s *scriptedScanner) Scan(context.Context) *engine.Report {
	r := s.reports[s.i]
	if s.i < len(s.reports)-1 {
		s.i++
	}
	return r
}

// recordingConnector captures every report dispatched to it.
type recordingConnector struct{ got []*engine.Report }

func (c *recordingConnector) Name() string { return "recording" }
func (c *recordingConnector) Send(_ context.Context, r *engine.Report) error {
	c.got = append(c.got, r)
	return nil
}

var _ connector.Connector = (*recordingConnector)(nil)

func TestLoopRunsPerTickAndDispatchesOnlyDeltas(t *testing.T) {
	a := fnd("vuln", "CVE-1", "pkg-a", engine.SeverityHigh)
	b := fnd("vuln", "CVE-2", "pkg-b", engine.SeverityCritical)

	sc := &scriptedScanner{reports: []*engine.Report{
		report(a),    // cycle 1: a new
		report(a),    // cycle 2: no change
		report(a, b), // cycle 3: b new
	}}
	rc := &recordingConnector{}
	w := &Watcher{Scanner: sc, Connectors: []connector.Connector{rc}, OnlyDeltas: true}

	tick := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan int)
	go func() { done <- w.Loop(ctx, tick) }()

	tick <- time.Unix(1, 0) // drive cycle 2
	tick <- time.Unix(2, 0) // drive cycle 3
	cancel()
	cycles := <-done

	if cycles != 3 {
		t.Fatalf("cycles = %d, want 3 (immediate + 2 ticks)", cycles)
	}
	// Only cycles 1 and 3 changed, so only 2 dispatches; each carries just the
	// new findings.
	if len(rc.got) != 2 {
		t.Fatalf("dispatched %d times, want 2 (deltas only); reports=%+v", len(rc.got), rc.got)
	}
	if len(rc.got[0].Findings) != 1 || rc.got[0].Findings[0].RuleID != "CVE-1" {
		t.Errorf("first dispatch should carry only CVE-1, got %+v", rc.got[0].Findings)
	}
	if len(rc.got[1].Findings) != 1 || rc.got[1].Findings[0].RuleID != "CVE-2" {
		t.Errorf("second dispatch should carry only CVE-2, got %+v", rc.got[1].Findings)
	}
}

func TestLoopStopsOnCancelledContext(t *testing.T) {
	sc := &scriptedScanner{reports: []*engine.Report{report()}}
	w := &Watcher{Scanner: sc}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before Loop starts
	cycles := w.Loop(ctx, make(chan time.Time))
	if cycles != 0 {
		t.Errorf("cancelled-before-start Loop should run 0 cycles, got %d", cycles)
	}
}

func TestRunDispatchesFullReportWhenNotOnlyDeltas(t *testing.T) {
	a := fnd("vuln", "CVE-1", "pkg-a", engine.SeverityHigh)
	b := fnd("vuln", "CVE-2", "pkg-b", engine.SeverityHigh)
	sc := &scriptedScanner{reports: []*engine.Report{report(a, b)}}
	rc := &recordingConnector{}
	w := &Watcher{Scanner: sc, Connectors: []connector.Connector{rc}, OnlyDeltas: false}
	w.Run(context.Background())
	if len(rc.got) != 1 || len(rc.got[0].Findings) != 2 {
		t.Fatalf("full-report mode should dispatch all findings; got %+v", rc.got)
	}
}
