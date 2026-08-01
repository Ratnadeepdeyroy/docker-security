// Package watch turns dsecrat's one-shot analysis into continuous monitoring. It
// re-runs the engine against a target on an interval, diffs each run against the
// previous one, and emits only the *delta* — findings that newly appeared or
// cleared — through the normal connectors. This is what makes the spec's
// "continuous re-scan / drift / clean-yesterday-vulnerable-today" controls real
// without adding any new detection logic: the modules are unchanged, only the
// scheduling and diffing are new.
//
// The core is split so it stays testable with zero wall-clock dependence:
//
//   - Diff is a pure function over two reports.
//   - Run performs a single scan+diff+dispatch cycle.
//   - Loop drives Run on a caller-supplied tick channel and stops on context
//     cancellation, so a test can feed synthetic ticks and assert deterministic
//     behavior; the CLI supplies a real time.Ticker.
package watch

import (
	"context"
	"sort"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/connector"
	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// Scanner produces a report for the watched target. It abstracts the engine so
// tests can inject a deterministic sequence of reports.
type Scanner interface {
	Scan(ctx context.Context) *engine.Report
}

// EngineScanner adapts an engine + target into a Scanner, running the named
// modules (empty = all).
type EngineScanner struct {
	Engine  *engine.Engine
	Target  *engine.Target
	Modules []string
}

// Scan runs one analysis pass.
func (e EngineScanner) Scan(ctx context.Context) *engine.Report {
	return e.Engine.Run(ctx, e.Target, e.Modules...)
}

// Delta is the difference between two consecutive scans: findings that appeared
// this run (New) and findings present last run but gone now (Cleared).
type Delta struct {
	New     []engine.Finding
	Cleared []engine.Finding
}

// Changed reports whether the delta carries any change at all.
func (d Delta) Changed() bool { return len(d.New) > 0 || len(d.Cleared) > 0 }

// findingKey is the stable identity of a finding across runs. Two findings with
// the same key are "the same issue"; a key that appears in the new run but not
// the old is a genuinely new finding (not a re-report of an existing one). The
// Location and RuleID/Resource triple is what distinguishes, e.g., the same CVE
// on two different packages.
func findingKey(f engine.Finding) string {
	loc := ""
	if f.Location != nil {
		loc = f.Location.Path
	}
	return f.Module + "\x00" + f.RuleID + "\x00" + f.Resource + "\x00" + loc
}

// Diff computes the New/Cleared delta between a previous and current report. A
// nil previous report means every current finding is New (the first run). The
// returned slices are sorted most-severe-first for stable, readable output.
func Diff(prev, cur *engine.Report) Delta {
	prevSet := map[string]engine.Finding{}
	if prev != nil {
		for _, f := range prev.Findings {
			prevSet[findingKey(f)] = f
		}
	}
	curSet := map[string]engine.Finding{}
	var d Delta
	if cur != nil {
		for _, f := range cur.Findings {
			k := findingKey(f)
			curSet[k] = f
			if _, seen := prevSet[k]; !seen {
				d.New = append(d.New, f)
			}
		}
	}
	for k, f := range prevSet {
		if _, still := curSet[k]; !still {
			d.Cleared = append(d.Cleared, f)
		}
	}
	sortFindings(d.New)
	sortFindings(d.Cleared)
	return d
}

func sortFindings(fs []engine.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity // most severe first
		}
		return findingKey(fs[i]) < findingKey(fs[j])
	})
}

// Observer is notified after every cycle, whether or not the delta changed. The
// CLI uses it to print a heartbeat line; tests use it to record cycles.
type Observer interface {
	OnCycle(rep *engine.Report, d Delta)
}

// ObserverFunc adapts a function to Observer.
type ObserverFunc func(rep *engine.Report, d Delta)

// OnCycle implements Observer.
func (f ObserverFunc) OnCycle(rep *engine.Report, d Delta) { f(rep, d) }

// Watcher runs continuous monitoring over one target.
type Watcher struct {
	Scanner    Scanner
	Connectors []connector.Connector
	Observer   Observer

	// OnlyDeltas, when true (the default behavior chosen by the CLI), dispatches
	// to connectors only when the delta is non-empty, so a stable target stays
	// quiet. When false, every cycle's full report is dispatched.
	OnlyDeltas bool

	prev *engine.Report
}

// Run performs exactly one scan+diff+dispatch cycle and returns the delta. It is
// the unit of work Loop repeats; calling it directly is how tests exercise a
// deterministic sequence without any timing.
func (w *Watcher) Run(ctx context.Context) Delta {
	cur := w.Scanner.Scan(ctx)
	d := Diff(w.prev, cur)
	w.prev = cur

	if w.Observer != nil {
		w.Observer.OnCycle(cur, d)
	}
	if len(w.Connectors) > 0 && (!w.OnlyDeltas || d.Changed()) {
		out := cur
		if w.OnlyDeltas {
			out = deltaReport(cur, d)
		}
		// Dispatch errors are surfaced by the connector layer's callers; a watch
		// loop must not abort on a single failed destination.
		_ = connector.Dispatch(ctx, out, w.Connectors...)
	}
	return d
}

// deltaReport builds a report containing only the newly-appeared findings, so a
// connector receives just the change rather than the full standing set. It
// copies the current report's metadata so downstream formatters still see a
// well-formed report.
func deltaReport(cur *engine.Report, d Delta) *engine.Report {
	r := &engine.Report{
		Tool:        cur.Tool,
		TargetType:  cur.TargetType,
		Target:      cur.Target,
		GeneratedAt: cur.GeneratedAt,
		Findings:    append([]engine.Finding(nil), d.New...),
		ModuleRuns:  cur.ModuleRuns,
	}
	return r
}

// Loop drives Run once immediately, then once per received tick, until the
// context is cancelled. The tick channel is injected so production passes a
// time.Ticker.C while tests pass a hand-fed channel — the loop itself contains
// no clock. It returns the number of cycles completed.
func (w *Watcher) Loop(ctx context.Context, tick <-chan time.Time) int {
	cycles := 0
	// Immediate first cycle so a watcher reports current state without waiting a
	// full interval.
	select {
	case <-ctx.Done():
		return cycles
	default:
	}
	w.Run(ctx)
	cycles++
	for {
		select {
		case <-ctx.Done():
			return cycles
		case _, ok := <-tick:
			if !ok {
				return cycles
			}
			w.Run(ctx)
			cycles++
		}
	}
}
