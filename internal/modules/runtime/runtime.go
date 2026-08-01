// Package runtime is the engine-module face of the runtime sensor. It replays a
// recorded telemetry stream (the offline capture a node's dsecrat-runtime daemon
// produces) through the deterministic detection core in internal/runtime and
// projects the resulting detections into engine.Findings, so runtime threats
// appear in the same unified scan report as static findings.
//
// It Supports container targets. The telemetry to analyze is supplied out-of-band
// (a recorded scenario file named in the target metadata, or inlined in the
// target content) — the module never touches a live kernel; that is the daemon's
// job on Linux. With no telemetry supplied the module is silent, so it never
// fabricates findings. The novel/behavioral detections stay off unless explicitly
// enabled via metadata, mirroring the core's off-by-default posture.
package runtime

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	rt "github.com/Ratnadeepdeyroy/docker-security/internal/runtime"
)

const moduleName = "runtime"

// Target metadata keys. All are optional; without an events source the module
// produces nothing.
const (
	// metaEvents is a filesystem path to a recorded scenario JSON (the offline
	// telemetry capture). When empty, the module falls back to Target.Content.
	metaEvents = "runtime.events"
	// metaEnableAgent turns on the novel AI-agent-runtime rule (DS-RAT-RT-100).
	metaEnableAgent = "runtime.enable_agent"
	// metaEnableAnomaly turns on baseline anomaly detection (DS-RAT-RT-050); it
	// additionally needs metaBaseline to point at a learned baseline file.
	metaEnableAnomaly = "runtime.enable_anomaly"
	// metaBaseline is a path to a learned baseline JSON (for anomaly detection).
	metaBaseline = "runtime.baseline"
	// metaEgressAllow is a comma-separated egress allowlist (domains/IPs/CIDRs).
	metaEgressAllow = "runtime.egress_allow"
)

// Module surfaces runtime detections in a scan report (CAPABILITY_SPEC domains
// 4 dynamic/behavior, 5 forensics, 11 detection/response).
type Module struct{}

// New returns a runtime module.
func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "Runtime threat detection: replays node telemetry and reports ATT&CK-mapped container detections (domains 4,5,11)"
}
func (m *Module) Domains() []string { return []string{"4", "5", "11"} }

// Supports handles container targets — the workload a runtime detection is about.
func (m *Module) Supports(t engine.TargetType) bool { return t == engine.TargetContainer }

// Analyze loads the telemetry for the target, runs the deterministic detector,
// and projects detections into findings scoped to the target container. With no
// telemetry available it returns nothing (not an error) — a scan of a container
// for which we hold no runtime data simply has no runtime findings.
func (m *Module) Analyze(ctx context.Context, t *engine.Target) ([]engine.Finding, error) {
	sc, err := m.loadTelemetry(t)
	if err != nil {
		return nil, err
	}
	if sc == nil {
		return nil, nil // no telemetry supplied → silent, by design
	}

	opts, err := buildOptions(t)
	if err != nil {
		return nil, err
	}

	det := rt.NewDetector(opts, sc.Images)
	dets, err := det.Run(ctx, rt.NewReplaySource(sc.Events))
	if err != nil {
		return nil, fmt.Errorf("runtime detection over telemetry: %w", err)
	}
	dets = scopeToContainer(dets, t.Location)

	findings := make([]engine.Finding, 0, len(dets)+1)
	findings = append(findings, summaryFinding(t, dets))
	for _, d := range dets {
		findings = append(findings, d.ToFinding(moduleName))
	}
	return findings, nil
}

// loadTelemetry resolves the recorded scenario from the metadata path or, failing
// that, from inlined target content. Returns (nil, nil) when neither is present.
func (m *Module) loadTelemetry(t *engine.Target) (*rt.Scenario, error) {
	if path := t.Metadata[metaEvents]; path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open runtime telemetry %q: %w", path, err)
		}
		defer f.Close()
		sc, err := rt.LoadScenario(f)
		if err != nil {
			return nil, fmt.Errorf("load runtime telemetry %q: %w", path, err)
		}
		return sc, nil
	}
	if len(t.Content) > 0 {
		sc, err := rt.LoadScenario(strings.NewReader(string(t.Content)))
		if err != nil {
			return nil, fmt.Errorf("load inlined runtime telemetry: %w", err)
		}
		return sc, nil
	}
	return nil, nil
}

// buildOptions maps target metadata to detector options. Optional rule groups are
// off unless explicitly requested, matching the core's posture.
func buildOptions(t *engine.Target) (rt.Options, error) {
	opts := rt.Options{
		EnableAgentRuntime: t.Metadata[metaEnableAgent] == "true",
		EnableAnomaly:      t.Metadata[metaEnableAnomaly] == "true",
	}
	if v := t.Metadata[metaEgressAllow]; v != "" {
		opts.EgressAllow = splitCSV(v)
	}
	if opts.EnableAnomaly {
		path := t.Metadata[metaBaseline]
		if path == "" {
			return opts, fmt.Errorf("%s=true requires %s to point at a baseline file", metaEnableAnomaly, metaBaseline)
		}
		b, err := loadBaseline(path)
		if err != nil {
			return opts, err
		}
		opts.Baseline = b
	}
	return opts, nil
}

// scopeToContainer narrows detections to the target container when the target
// names one and at least one detection matches; otherwise every detection in the
// stream is surfaced (the capture was already scoped by the caller).
func scopeToContainer(dets []rt.Detection, location string) []rt.Detection {
	if location == "" {
		return dets
	}
	var matched []rt.Detection
	for _, d := range dets {
		if d.Container.ID == location || d.Container.Name == location {
			matched = append(matched, d)
		}
	}
	if len(matched) == 0 {
		return dets
	}
	return matched
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
