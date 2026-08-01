package store

import (
	"context"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	sbomlib "github.com/Ratnadeepdeyroy/docker-security/internal/sbom"
)

// --- Ingest adapters -----------------------------------------------------
//
// These bridge the engine/SBOM domain types into a Scan. They live in their own
// file so the query core (store.go, query.go) has no dependency on the SBOM
// package and stays trivially unit-testable; only callers that actually build an
// inventory pull in internal/sbom.

// ComponentsFromSBOM flattens an SBOM into the store's lightweight component
// records. A nil SBOM yields nil, so callers can pass the result of a best-effort
// SBOM build directly (a Dockerfile target has no SBOM, and that is fine).
func ComponentsFromSBOM(doc *sbomlib.SBOM) []Component {
	if doc == nil {
		return nil
	}
	out := make([]Component, 0, len(doc.Components))
	for _, c := range doc.Components {
		out = append(out, Component{
			Name:    c.Name,
			Version: c.Version,
			Type:    string(c.Type),
			PURL:    c.PURL,
		})
	}
	return out
}

// BuildScan assembles a Scan from a finished Report plus optional inventory and
// ownership labels. RecordedAt is taken from the Report so the persisted record
// carries the same (injected, deterministic) timestamp the scan ran with; if the
// report has no timestamp the caller-supplied fallback is used.
//
// image is the canonical identity used for grouping and trends. When empty it
// falls back to the report's target, so a caller can always persist something
// addressable.
func BuildScan(image string, rep *engine.Report, comps []Component, labels map[string]string, fallback time.Time) *Scan {
	sc := &Scan{
		Image:      image,
		Report:     rep,
		Components: comps,
		Labels:     labels,
	}
	if rep != nil {
		sc.TargetType = string(rep.TargetType)
		if sc.Image == "" {
			sc.Image = rep.Target
		}
		if !rep.GeneratedAt.IsZero() {
			sc.RecordedAt = rep.GeneratedAt.UTC()
		}
	}
	if sc.RecordedAt.IsZero() {
		sc.RecordedAt = fallback.UTC()
	}
	return sc
}

// RunAndBuild runs the engine against target and (best-effort, when withSBOM is
// set) builds its component inventory, returning a Scan ready to Put. It does
// not persist — the caller decides whether to store it. An empty names slice
// runs every module. This is the single scan-and-assemble path shared by the
// HTTP API and the MCP scan_target tool, so both produce identically-shaped
// records.
func RunAndBuild(ctx context.Context, eng *engine.Engine, target *engine.Target, names []string, image string, labels map[string]string, withSBOM bool, now time.Time) *Scan {
	rep := eng.Run(ctx, target, names...)
	var comps []Component
	if withSBOM {
		if doc, err := sbomlib.Generate(ctx, target); err == nil {
			comps = ComponentsFromSBOM(doc)
		}
	}
	if image == "" {
		image = target.Location
	}
	return BuildScan(image, rep, comps, labels, now)
}
