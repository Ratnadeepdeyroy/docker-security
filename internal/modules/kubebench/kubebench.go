package kubebench

import (
	"context"
	"strconv"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/compliance"
	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

const moduleName = "kubebench"

// Module is the CIS Kubernetes Benchmark capability (CAPABILITY_SPEC domain 10).
// It audits a cluster from a collected evidence snapshot, auto-selecting a
// version- and platform-matched profile, and projects each control result into
// the unified Finding model.
type Module struct{}

// New returns a kubebench module.
func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "CIS Kubernetes Benchmark: control-plane, etcd, node, and policy controls (domain 10)"
}
func (m *Module) Domains() []string { return []string{"10"} }

// Supports handles filesystem targets (a cluster evidence directory/file).
// There is no dedicated cluster TargetType today; see NOTES.md for the proposed
// engine addition. The module stays quiet when the target holds no cluster
// evidence, so a plain filesystem scan is unaffected.
func (m *Module) Supports(t engine.TargetType) bool {
	return t == engine.TargetFilesystem
}

// Analyze loads the cluster evidence and runs the version-matched benchmark.
// Missing/unreadable inputs degrade to INFO rather than erroring. The
// continuous-compliance narrative (AI-age feature) stays OFF unless the caller
// opts in via target metadata "compliance.narrative"="true".
func (m *Module) Analyze(_ context.Context, t *engine.Target) ([]engine.Finding, error) {
	ev, err := Load(t.Location)
	if err != nil {
		return nil, err
	}
	if !ev.hasEvidence() {
		return nil, nil // not a cluster snapshot; say nothing on a plain fs scan
	}

	rep := Assess(ev)
	findings := compliance.Findings(moduleName, rep)

	if t.Metadata != nil && t.Metadata["compliance.narrative"] == "true" {
		nar := compliance.BuildNarrative(rep, compliance.NarrativeOptions{Now: narrativeClock(t)})
		findings = append(findings, engine.Finding{
			RuleID:      "DS-RAT-CIS-NARRATIVE",
			Module:      moduleName,
			Severity:    engine.SeverityInfo,
			Title:       "Continuous-compliance narrative",
			Description: nar.Text(),
			Resource:    nar.Benchmark,
			Metadata:    map[string]string{"score": strconv.Itoa(nar.Score), "benchmark": nar.Benchmark},
		})
	}
	return findings, nil
}

// narrativeClock returns the injected timestamp for deterministic narrative
// output in the analysis path (analysis never reads the wall clock). Absent
// metadata yields the zero time.
func narrativeClock(t *engine.Target) time.Time {
	if t.Metadata != nil {
		if s := t.Metadata["compliance.now"]; s != "" {
			if ts, err := time.Parse(time.RFC3339, s); err == nil {
				return ts
			}
		}
	}
	return time.Time{}
}
