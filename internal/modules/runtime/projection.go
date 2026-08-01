package runtime

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	rt "github.com/Ratnadeepdeyroy/docker-security/internal/runtime"
)

// This file holds the projection glue: turning a detection run into report
// artifacts (a gating-neutral summary finding) and loading the optional baseline.

// summaryFinding is a single INFO finding summarizing the run — a quick "what did
// the sensor see for this workload" line at the top of the runtime section. It is
// INFO so it never affects gating, mirroring other modules' summary rows.
func summaryFinding(t *engine.Target, dets []rt.Detection) engine.Finding {
	counts := map[engine.Severity]int{}
	for _, d := range dets {
		counts[d.Severity]++
	}
	return engine.Finding{
		RuleID:   "DS-RAT-RT-000",
		Module:   moduleName,
		Severity: engine.SeverityInfo,
		Title: fmt.Sprintf("Runtime telemetry analyzed: %d detection(s) (critical=%d high=%d medium=%d low=%d)",
			len(dets), counts[engine.SeverityCritical], counts[engine.SeverityHigh], counts[engine.SeverityMedium], counts[engine.SeverityLow]),
		Description: "Recorded runtime telemetry for this container was replayed through the detection rule set. Detections below are mapped to MITRE ATT&CK for Containers.",
		Resource:    t.Location,
		References:  []string{"https://attack.mitre.org/matrices/enterprise/containers/"},
		Metadata: map[string]string{
			"ruleset":    rt.RuleSetVersion,
			"detections": fmt.Sprintf("%d", len(dets)),
		},
	}
}

// loadBaseline reads a learned baseline JSON for anomaly detection. It bounds the
// read so a hostile file cannot exhaust memory.
func loadBaseline(path string) (*rt.Baseline, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open baseline %q: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 16<<20)) // 16 MiB cap
	if err != nil {
		return nil, fmt.Errorf("read baseline %q: %w", path, err)
	}
	var b rt.Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline %q: %w", path, err)
	}
	return &b, nil
}
