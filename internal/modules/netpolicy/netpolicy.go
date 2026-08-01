// Package netpolicy is the engine module for Phase 6 (CAPABILITY_SPEC domain 6):
// network egress analysis and least-privilege policy generation. It is a thin
// adapter — the flow model and detection heuristics live in internal/netmon;
// this package loads a recorded capture from a Target, runs netmon over it, and
// projects the resulting anomalies and posture observations onto engine.Finding.
//
// It also *generates* least-privilege artifacts from an observed baseline: a
// Kubernetes NetworkPolicy, a companion DNS/FQDN egress allowlist, and a
// default-deny egress policy. Generation is advisory by design — the module and
// the `dsecrat net` command emit policy for review or agent-application, never
// enforce it. That keeps us an observation-and-recommendation layer, not a
// dataplane, exactly as the phase handoff requires.
//
// Two AI-age features ride on top, both OFF by default (opt in via Target
// metadata or CLI flags): egress intent modelling (intended-vs-anomalous
// destinations with a rationale an agent can approve) and agent egress
// governance (watching AI-agent workloads for egress to unknown model hosts).
package netpolicy

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/netmon"
)

const moduleName = "netpolicy"

// Target metadata keys. All are opt-in: absent keys keep the deterministic,
// feature-off defaults so a generic filesystem scan stays quiet and stable.
const (
	// metaNowUnix injects the reference time (unix seconds) for windowed
	// detection, keeping analysis reproducible in tests and CI.
	metaNowUnix = "netpolicy.now_unix"
	// metaIntent enables egress intent modelling (AI-age feature).
	metaIntent = "netpolicy.intent"
	// metaAgentEgress enables agent egress governance (AI-age feature).
	metaAgentEgress = "netpolicy.agent_egress"
	// metaNamespace names the Kubernetes namespace for generated policy.
	metaNamespace = "netpolicy.namespace"
)

// Module is the network egress-analysis capability.
type Module struct{}

// New returns a netpolicy module.
func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "Network egress analysis & least-privilege policy generation from observed flows (domain 6)"
}
func (m *Module) Domains() []string { return []string{"6"} }

// Supports handles filesystem targets: the carrier for a recorded network
// capture (JSON). There is no dedicated "flow capture" target type yet — see
// NOTES.md for the proposed engine change. Until then a filesystem target whose
// content is a capture is analysed; anything that is not a capture yields no
// findings, so ordinary filesystem scans are unaffected.
func (m *Module) Supports(t engine.TargetType) bool {
	return t == engine.TargetFilesystem
}

// Analyze loads the capture from the target, runs netmon detection, and projects
// anomalies plus network-posture observations onto findings. When the target is
// not a network capture it returns nothing so generic scans stay silent.
func (m *Module) Analyze(_ context.Context, t *engine.Target) ([]engine.Finding, error) {
	capture, err := loadCapture(t)
	if err != nil {
		return nil, err
	}
	if capture == nil {
		return nil, nil // not a capture: stay quiet
	}

	report := netmon.Analyze(capture, optionsFromTarget(t))

	findings := make([]engine.Finding, 0, len(report.Anomalies)+4)
	findings = append(findings, summaryFinding(capture, report))
	findings = append(findings, postureFindings(capture, report)...)
	for _, a := range report.Anomalies {
		findings = append(findings, anomalyToFinding(a))
	}
	return findings, nil
}

// loadCapture pulls a capture out of a filesystem target: inlined Content first
// (the engine may have pre-loaded it), else the file at Location. A parse
// failure on inlined content is reported; a Location that simply is not a
// capture returns (nil, nil) so unrelated filesystem targets are ignored.
func loadCapture(t *engine.Target) (*netmon.Capture, error) {
	if len(t.Content) > 0 {
		c, err := netmon.DecodeCapture(strings.NewReader(string(t.Content)))
		if err != nil {
			return nil, fmt.Errorf("decode inlined capture %q: %w", t.Location, err)
		}
		return c, nil
	}
	if t.Location == "" {
		return nil, nil
	}
	c, err := netmon.LoadCapture(t.Location)
	if err != nil {
		// A filesystem target that is not our capture format is not our concern;
		// only surface an error when the content clearly tried to be a capture.
		return nil, nil
	}
	return c, nil
}

// optionsFromTarget builds netmon.Options from opt-in target metadata, leaving
// AI-age features off unless explicitly enabled.
func optionsFromTarget(t *engine.Target) netmon.Options {
	var o netmon.Options
	if v := t.Metadata[metaNowUnix]; v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil && sec > 0 {
			o.Now = time.Unix(sec, 0).UTC()
		}
	}
	o.EnableIntent = isTrue(t.Metadata[metaIntent])
	o.EnableAgentEgress = isTrue(t.Metadata[metaAgentEgress])
	return o
}

func isTrue(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
