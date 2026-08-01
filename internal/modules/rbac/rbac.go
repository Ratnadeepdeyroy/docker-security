// Package rbac is the engine module wrapper around internal/rbac. It projects
// identity/RBAC risks (over-permissive roles, exposed tokens, privilege-
// escalation paths, docker-group/socket exposure) into the unified Finding
// model. The heavy analysis lives in internal/rbac; this file only adapts the
// Risk values onto engine.Finding and wires the optional NHI feature to a target
// metadata flag so it stays off by default.
package rbac

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	rbaclib "github.com/Ratnadeepdeyroy/docker-security/internal/rbac"
)

const moduleName = "rbac"

// Metadata keys a caller can set on a Target to tune the RBAC analysis. They are
// opt-in: absent keys keep the deterministic, feature-off defaults.
const (
	// metaEnableNHI turns on the non-human-identity risk graph (AI-age feature).
	metaEnableNHI = "rbac.nhi"
	// metaNowUnix injects the reference time (unix seconds) for dormancy, so the
	// NHI feature stays deterministic in tests and reproducible in CI.
	metaNowUnix = "rbac.now_unix"
)

// Module is the identity/RBAC analysis capability (CAPABILITY_SPEC domain 15,
// plus the Docker-side identity surface).
type Module struct{}

// New returns an RBAC module.
func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "Identity/RBAC risk: over-privilege, exposed tokens, and privilege-escalation paths (domain 15)"
}
func (m *Module) Domains() []string { return []string{"15"} }

// Supports handles filesystem targets: a directory or file of Kubernetes RBAC
// JSON (and our DockerHost descriptor). There is no dedicated k8s/config target
// type yet — see NOTES.md for the proposed engine change; until then a
// filesystem target is the carrier, and non-RBAC inputs produce no findings.
func (m *Module) Supports(t engine.TargetType) bool {
	return t == engine.TargetFilesystem
}

// Analyze loads the cluster from the target, runs the analysis, and projects each
// Risk onto a Finding. When the target holds no RBAC objects, it returns nothing
// so generic filesystem scans stay quiet.
func (m *Module) Analyze(_ context.Context, t *engine.Target) ([]engine.Finding, error) {
	cluster, err := loadCluster(t)
	if err != nil {
		return nil, err
	}
	report := rbaclib.Analyze(cluster, optionsFromTarget(t))
	if len(report.Risks) == 0 {
		return nil, nil
	}

	findings := make([]engine.Finding, 0, len(report.Risks)+1)
	// A gating-neutral summary so the module always leaves a breadcrumb when it
	// did find a cluster to analyze.
	findings = append(findings, engine.Finding{
		RuleID:      "DS-RAT-RBAC-000",
		Module:      moduleName,
		Severity:    engine.SeverityInfo,
		Title:       fmt.Sprintf("RBAC analyzed: %d risk(s) across identities", len(report.Risks)),
		Description: summary(report),
		Resource:    t.Location,
		References:  []string{"https://kubernetes.io/docs/concepts/security/rbac-good-practices/"},
	})
	for _, r := range report.Risks {
		findings = append(findings, toFinding(r))
	}
	return findings, nil
}

// --- Loading -------------------------------------------------------------

// loadCluster reads the RBAC objects from the target: inlined Content wins (the
// caller already loaded them), otherwise we read from Location (a file or dir).
func loadCluster(t *engine.Target) (*rbaclib.Cluster, error) {
	if len(t.Content) > 0 {
		return rbaclib.LoadBytes(t.Content)
	}
	if t.Location == "" {
		return rbaclib.LoadBytes(nil)
	}
	return rbaclib.LoadPath(t.Location)
}

// optionsFromTarget maps opt-in target metadata onto analysis options.
func optionsFromTarget(t *engine.Target) rbaclib.Options {
	opts := rbaclib.Options{}
	if t.Metadata[metaEnableNHI] == "true" {
		opts.EnableNHI = true
	}
	if v := t.Metadata[metaNowUnix]; v != "" {
		if sec, err := strconv.ParseInt(v, 10, 64); err == nil {
			opts.Now = time.Unix(sec, 0).UTC()
		}
	}
	return opts
}

// --- Projection ----------------------------------------------------------

// toFinding maps one Risk onto a Finding, preserving the escalation path and the
// structured remediation metadata for agent consumers.
func toFinding(r rbaclib.Risk) engine.Finding {
	resource := r.Resource
	if resource == "" {
		resource = r.Subject
	}
	meta := map[string]string{}
	for k, v := range r.Meta {
		meta[k] = v
	}
	if r.Subject != "" {
		meta["subject"] = r.Subject
	}
	if len(r.Path) > 0 {
		meta["escalationPath"] = strings.Join(r.Path, " -> ")
	}
	if len(meta) == 0 {
		meta = nil
	}
	return engine.Finding{
		RuleID:      r.RuleID,
		Module:      moduleName,
		Severity:    r.Severity,
		Title:       r.Title,
		Description: r.Description,
		Resource:    resource,
		Remediation: r.Remediation,
		References:  r.References,
		Metadata:    meta,
	}
}

// summary renders a compact severity breakdown for the DS-RAT-RBAC-000 finding.
func summary(rep *rbaclib.Report) string {
	var parts []string
	for _, sev := range []engine.Severity{engine.SeverityCritical, engine.SeverityHigh, engine.SeverityMedium, engine.SeverityLow, engine.SeverityInfo} {
		if n := rep.Counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev.String()))
		}
	}
	return strings.Join(parts, ", ")
}
