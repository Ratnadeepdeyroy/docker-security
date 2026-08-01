package dockerbench

import (
	"context"

	"github.com/Ratnadeepdeyroy/docker-security/internal/compliance"
	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

const moduleName = "dockerbench"

// Module is the CIS Docker Benchmark capability (CAPABILITY_SPEC domain 10). It
// audits a Docker host/daemon from a collected evidence snapshot and projects
// each control result into the unified Finding model.
type Module struct{}

// New returns a dockerbench module.
func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "CIS Docker Benchmark: host, daemon, config-file, and runtime controls (domain 10)"
}
func (m *Module) Domains() []string { return []string{"10"} }

// Supports handles filesystem targets (an evidence directory/file) and
// container targets. There is no dedicated host/daemon TargetType today; see
// NOTES.md for the proposed engine addition. The module stays quiet when the
// target holds no Docker evidence, so a plain filesystem scan is unaffected.
func (m *Module) Supports(t engine.TargetType) bool {
	return t == engine.TargetFilesystem || t == engine.TargetContainer
}

// Analyze loads the evidence at the target location and runs the benchmark.
// Missing or unreadable inputs degrade to INFO controls rather than erroring,
// so the run never crashes on partial evidence. The continuous-compliance
// narrative (AI-age feature) stays OFF unless the caller opts in via the
// target metadata key "compliance.narrative"="true".
func (m *Module) Analyze(_ context.Context, t *engine.Target) ([]engine.Finding, error) {
	path := evidencePath(t)
	ev, err := Load(path)
	if err != nil {
		return nil, err
	}
	// On a generic filesystem scan with no Docker evidence, say nothing.
	if !ev.hasDaemonEvidence() && t.Type == engine.TargetFilesystem {
		return nil, nil
	}

	rep := Assess(ev)
	findings := compliance.Findings(moduleName, rep)

	if optNarrative(t) {
		// Deterministic: the clock is injected from target metadata (or zero).
		nar := compliance.BuildNarrative(rep, compliance.NarrativeOptions{Now: narrativeClock(t)})
		findings = append(findings, narrativeFinding(nar))
	}
	return findings, nil
}

// narrativeFinding wraps the compliance narrative as a single INFO finding so an
// agent can retrieve the "state of compliance" brief from the normal stream.
func narrativeFinding(n *compliance.Narrative) engine.Finding {
	return engine.Finding{
		RuleID:      "DS-RAT-CIS-NARRATIVE",
		Module:      moduleName,
		Severity:    engine.SeverityInfo,
		Title:       "Continuous-compliance narrative",
		Description: n.Text(),
		Resource:    n.Benchmark,
		Metadata: map[string]string{
			"score":     itoa(n.Score),
			"benchmark": n.Benchmark,
		},
	}
}
