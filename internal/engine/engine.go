package engine

import (
	"context"
	"fmt"
	"sort"
)

// Engine runs registered modules against a target and aggregates the results.
type Engine struct {
	registry *Registry
}

// New builds an engine over the given module registry.
func New(r *Registry) *Engine { return &Engine{registry: r} }

// Run executes matching modules against the target. If names is non-empty, only
// those modules are considered (still filtered by Supports); otherwise every
// registered module that supports the target type runs. A module returning an
// error is recorded in the report but does not abort the run.
func (e *Engine) Run(ctx context.Context, t *Target, names ...string) *Report {
	rep := &Report{
		Tool:        "docker-security",
		TargetType:  t.Type,
		Target:      t.Location,
		GeneratedAt: stamp(),
	}

	var mods []Module
	if len(names) > 0 {
		for _, n := range names {
			if m, ok := e.registry.Get(n); ok {
				mods = append(mods, m)
			}
		}
	} else {
		mods = e.registry.All()
	}

	for i, m := range mods {
		if !m.Supports(t.Type) {
			continue
		}
		// A cancelled context (deadline exceeded, caller gave up, ...) must
		// stop the scan cleanly rather than let it silently run to
		// completion: record every remaining supported module as not run so
		// the report can't be mistaken for a full scan.
		if err := ctx.Err(); err != nil {
			for _, rem := range mods[i:] {
				if !rem.Supports(t.Type) {
					continue
				}
				rep.ModuleRuns = append(rep.ModuleRuns, ModuleRun{
					Module: rem.Name(),
					Error:  "not run: " + err.Error(),
				})
			}
			break
		}

		run := ModuleRun{Module: m.Name()}
		findings, err := runModule(ctx, m, t)
		if err != nil {
			run.Error = err.Error()
		}
		rep.Add(findings...)
		rep.ModuleRuns = append(rep.ModuleRuns, run)
	}

	sortFindings(rep.Findings)
	return rep
}

// runModule invokes a single module's Analyze with panic recovery, so a
// module that panics on hostile or malformed input (e.g. a crafted
// Dockerfile or a corrupt image layer) is isolated: its failure is recorded
// as that module's error and the scan continues with the remaining modules.
// The recover is scoped to one module's call, not the whole loop, so a
// single panic can never abort modules that haven't run yet. The recovered
// value is stringified into the error; the stack trace is deliberately kept
// out of user-facing output.
func runModule(ctx context.Context, m Module, t *Target) (findings []Finding, err error) {
	defer func() {
		if r := recover(); r != nil {
			findings = nil
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return m.Analyze(ctx, t)
}

// sortFindings orders findings by severity (desc) then by location.
func sortFindings(fs []Finding) {
	line := func(f Finding) int {
		if f.Location != nil {
			return f.Location.StartLine
		}
		return 0
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity != fs[j].Severity {
			return fs[i].Severity > fs[j].Severity
		}
		if fs[i].Resource != fs[j].Resource {
			return fs[i].Resource < fs[j].Resource
		}
		return line(fs[i]) < line(fs[j])
	})
}
