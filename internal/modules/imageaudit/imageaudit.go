// Package imageaudit inspects a *built* container image — its configuration and
// its layer history — and reports hardening violations mapped to the CIS Docker
// Benchmark image controls (CIS-DI-*). Where the Dockerfile linter (phase 1a)
// audits the recipe, this module audits the baked artifact, so it works even on
// images that shipped with no Dockerfile at all: distroless base images, vendor
// images, anything you can `docker save`.
//
// It reads the image via internal/oci (config JSON + per-layer file trees) and
// is deliberately split into a deterministic CIS core and an optional,
// off-by-default enrichment layer (the attack-surface score, see surface.go).
// The core never reads the wall clock or a random source: the same image always
// yields byte-identical findings, which is what the golden test pins.
package imageaudit

import (
	"context"
	"fmt"
	"sort"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

const moduleName = "imageaudit"

// Module is the built-image configuration & CIS-audit capability. It is
// configured through functional options; the zero value (from New()) is the
// deterministic CIS baseline with every enrichment feature off.
type Module struct {
	// attackSurface enables the composite attack-surface score + agent-appliable
	// hardening plan (DS-RAT-IMG-100). It is off by default because it is an
	// opinionated enrichment, not a CIS control, and we never gate correctness
	// on an enrichment layer (SHARED_CONTRACT §4).
	attackSurface bool
}

// Option configures a Module at construction time.
type Option func(*Module)

// WithAttackSurfaceScore turns on the DS-RAT-IMG-100 attack-surface score and
// hardening plan. Callers (a CLI flag, an MCP request) opt in explicitly.
func WithAttackSurfaceScore() Option {
	return func(m *Module) { m.attackSurface = true }
}

// New returns an image-audit module. With no options it is the pure CIS
// baseline; pass WithAttackSurfaceScore to add the enrichment finding.
func New(opts ...Option) *Module {
	m := &Module{}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "Built-image config & CIS Docker Benchmark audit (root, ports, secrets, setuid, provenance)"
}

// Domains covers CAPABILITY_SPEC domain 3 (image hardening) and the image side
// of domain 10 (exposed ports / sensitive mounts).
func (m *Module) Domains() []string { return []string{"3", "10"} }

func (m *Module) Supports(t engine.TargetType) bool { return t == engine.TargetImage }

// --- Analysis orchestration --------------------------------------------------

// auditContext is the fully-loaded subject an individual rule reasons over. It
// is assembled once per Analyze call so rules never re-parse or re-flatten.
type auditContext struct {
	name  string       // human image reference (repo tag, else location)
	cfg   *imageConfig // parsed image configuration
	img   *oci.Image   // raw image, for per-layer history/whiteout inspection
	files []*oci.File  // effective (flattened) filesystem, path-sorted
	// probe is the one-pass classification of files (shells, package managers,
	// setuid). Computed once in Analyze so every rule and the surface score read
	// the same scan rather than re-walking the tree.
	probe surfaceProbe
}

// Analyze loads the image, parses its config, and runs the rule set. Per the
// engine contract a rule failure is recorded, never fatal; here the only
// fallible steps are load and config-parse, and a genuine load failure is worth
// surfacing to the caller as an error (the engine records it and continues).
func (m *Module) Analyze(ctx context.Context, t *engine.Target) ([]engine.Finding, error) {
	if t.Type != engine.TargetImage {
		return nil, fmt.Errorf("imageaudit: unsupported target type %q (want image)", t.Type)
	}
	img, err := t.Image()
	if err != nil {
		return nil, fmt.Errorf("imageaudit: load image %q: %w", t.Location, err)
	}
	cfg, err := parseConfig(img.Config)
	if err != nil {
		return nil, fmt.Errorf("imageaudit: %q: %w", t.Location, err)
	}

	files := img.Flatten().Files()
	ac := &auditContext{
		name:  imageName(img, t.Location),
		cfg:   cfg,
		img:   img,
		files: files,
		probe: probeFiles(files),
	}

	var findings []engine.Finding
	for _, r := range coreRules {
		if err := ctx.Err(); err != nil {
			return findings, err
		}
		findings = append(findings, r(ac)...)
	}
	if m.attackSurface {
		findings = append(findings, surfaceFinding(ac))
	}

	sortFindings(findings)
	return findings, nil
}

// imageName prefers the image's first repo tag, falling back to the load path,
// so a finding's Resource identifies the image a human would recognize.
func imageName(img *oci.Image, location string) string {
	if len(img.RepoTags) > 0 && img.RepoTags[0] != "" {
		return img.RepoTags[0]
	}
	return location
}

// sortFindings gives the module a stable, self-contained order (by rule id then
// resource) independent of the engine's later severity sort, so the golden test
// can pin this module's output directly.
func sortFindings(fs []engine.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].RuleID != fs[j].RuleID {
			return fs[i].RuleID < fs[j].RuleID
		}
		return fs[i].Resource < fs[j].Resource
	})
}

// mk builds a finding with this module's identity pre-filled. Image-config
// findings have no source line, so Location is left nil and Resource carries
// the concrete subject (image name, port, path).
func mk(id string, sev engine.Severity, resource, title, desc, remediation string, refs ...string) engine.Finding {
	return engine.Finding{
		RuleID:      id,
		Module:      moduleName,
		Severity:    sev,
		Title:       title,
		Description: desc,
		Remediation: remediation,
		Resource:    resource,
		References:  refs,
	}
}
