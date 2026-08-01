// Package secrets is the engine module wrapper around internal/secrets. It runs
// the secret-detection engine against Dockerfiles, filesystems, and images
// (layer-aware, including content deleted by a later layer) and projects each
// Detection into the unified Finding model. Findings are value-free: they carry
// a fingerprint, type, location, and verification state — never the secret.
//
// Optional behaviour is driven entirely by Target.Metadata, so the CLI/HTTP
// frontends can toggle it without any new plumbing and every run stays
// reproducible:
//
//	secrets.classifier=true    enable the semantic entropy sweep (off by default)
//	secrets.verify=true        enable opt-in live verification (network!)
//	secrets.baseline=<path>    suppress findings accepted in a baseline file
//
// Verification is the only feature that touches the network and is off unless
// explicitly requested; tests never enable it.
package secrets

import (
	"context"
	"fmt"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
	"github.com/Ratnadeepdeyroy/docker-security/internal/secrets"
)

const moduleName = "secrets"

// Module is the secret-detection capability (CAPABILITY_SPEC domain 7).
type Module struct{}

// New returns a secrets module.
func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "Detect embedded credentials in images (all layers, incl. deleted), filesystems & Dockerfiles (domain 7)"
}
func (m *Module) Domains() []string { return []string{"7"} }

// Supports reports the target types the module scans.
func (m *Module) Supports(t engine.TargetType) bool {
	return t == engine.TargetImage || t == engine.TargetFilesystem || t == engine.TargetDockerfile
}

// Analyze dispatches on target type, runs the scanner, and maps detections to
// findings. A failure to load the target is returned as an error; a scanner
// that simply finds nothing returns no findings and no error.
func (m *Module) Analyze(ctx context.Context, t *engine.Target) ([]engine.Finding, error) {
	scanner, err := buildScanner(t.Metadata)
	if err != nil {
		return nil, err
	}

	var dets []secrets.Detection
	switch t.Type {
	case engine.TargetDockerfile:
		dets = scanner.ScanDockerfile(ctx, t.Location, t.Content)
	case engine.TargetFilesystem:
		tree, err := oci.TreeFromDir(t.Location)
		if err != nil {
			return nil, fmt.Errorf("secrets: scan filesystem %q: %w", t.Location, err)
		}
		dets = scanner.ScanTree(ctx, tree)
	case engine.TargetImage:
		img, err := t.Image()
		if err != nil {
			return nil, fmt.Errorf("secrets: load image %q: %w", t.Location, err)
		}
		dets = scanner.ScanImage(ctx, img)
	default:
		return nil, fmt.Errorf("secrets: unsupported target type %q", t.Type)
	}

	findings := make([]engine.Finding, 0, len(dets))
	for _, d := range dets {
		findings = append(findings, toFinding(d))
	}
	return findings, nil
}

// buildScanner assembles a Scanner from opt-in Target.Metadata flags. Unknown or
// absent flags leave the high-signal, offline defaults in place.
func buildScanner(meta map[string]string) (*secrets.Scanner, error) {
	var opts []secrets.Option
	if meta["secrets.classifier"] == "true" {
		opts = append(opts, secrets.WithClassifier(secrets.HeuristicClassifier{}))
	}
	if meta["secrets.verify"] == "true" {
		// Network-facing and explicitly opt-in. Verification only raises the
		// severity of a confirmed-live key; it never changes what is detected.
		opts = append(opts, secrets.WithVerifier(secrets.HTTPVerifier{}))
	}
	if path := meta["secrets.baseline"]; path != "" {
		b, err := secrets.LoadBaseline(path)
		if err != nil {
			return nil, fmt.Errorf("secrets: %w", err)
		}
		opts = append(opts, secrets.WithBaseline(b))
	}
	return secrets.New(opts...), nil
}
