// Package license is the engine module that gates an image's component licenses
// against an allow/deny policy (CAPABILITY_SPEC domain 1 — license-policy
// gating). It generates the SBOM, evaluates each component's declared licenses
// with internal/license, and emits DS-RAT-LIC-* findings that flow into the normal
// report and the `dsecrat policy eval` CI gate.
//
// The gate is opt-in and configured entirely through target metadata, so it
// stays quiet unless an operator sets a policy:
//
//	license.deny=GPL-3.0-only,AGPL-3.0-only   comma-separated SPDX deny list
//	license.allow=MIT,Apache-2.0,BSD-3-Clause allowlist (anything else denied)
//	license.deny-classes=strong-copyleft,network-copyleft
//	license.flag-unknown=true                 deny unrecognized licenses
//	license.flag-unlicensed=true              deny components with no license
package license

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	liclib "github.com/Ratnadeepdeyroy/docker-security/internal/license"
	sbomlib "github.com/Ratnadeepdeyroy/docker-security/internal/sbom"
)

const moduleName = "license"

// Module implements the license-policy gate.
type Module struct{}

// New returns a license module.
func New() *Module { return &Module{} }

// Register adds the license module to a registry.
func Register(r *engine.Registry) { r.Register(New()) }

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "License-policy gate: allow/deny SPDX licenses & copyleft classes over the SBOM (domain 1)"
}
func (m *Module) Domains() []string { return []string{"1", "8"} }

func (m *Module) Supports(t engine.TargetType) bool {
	return t == engine.TargetImage || t == engine.TargetFilesystem
}

// Analyze generates the SBOM and evaluates each component's licenses against the
// policy from target metadata. It returns nothing when no policy is configured,
// so the module is inert by default.
func (m *Module) Analyze(ctx context.Context, t *engine.Target) ([]engine.Finding, error) {
	pol := policyFromMetadata(t.Metadata)
	if pol.Empty() {
		return nil, nil
	}

	doc, err := sbomlib.Generate(ctx, t)
	if err != nil {
		return nil, err
	}

	// Deny severity is configurable; default high (a distributed copyleft
	// violation is a real legal exposure, not informational).
	sev := engine.SeverityHigh
	if s := t.Metadata["license.severity"]; s != "" {
		if parsed := engine.ParseSeverity(s); parsed != engine.SeverityUnknown {
			sev = parsed
		}
	}

	var findings []engine.Finding
	for _, c := range doc.Components {
		lic := toLicenseIDs(c.Licenses)
		v := pol.Evaluate(lic)
		if !v.Denied {
			continue
		}
		findings = append(findings, engine.Finding{
			RuleID:      ruleForReason(v.Reason),
			Module:      moduleName,
			Severity:    sev,
			Title:       titleForReason(v, c),
			Description: describe(v, c),
			Resource:    componentRef(c),
			Remediation: remediation(v),
			References:  []string{"https://spdx.org/licenses/"},
			Metadata: map[string]string{
				"component":     c.Name,
				"version":       c.Version,
				"license":       v.License,
				"license_class": string(v.Class),
				"reason":        string(v.Reason),
			},
		})
	}
	// Stable, most-severe-agnostic ordering (all share sev): by component ref.
	sort.SliceStable(findings, func(i, j int) bool { return findings[i].Resource < findings[j].Resource })
	return findings, nil
}

// policyFromMetadata builds a license.Policy from target metadata keys.
func policyFromMetadata(meta map[string]string) *liclib.Policy {
	if meta == nil {
		return &liclib.Policy{}
	}
	p := &liclib.Policy{
		Allow:          splitCSV(meta["license.allow"]),
		Deny:           splitCSV(meta["license.deny"]),
		FlagUnknown:    meta["license.flag-unknown"] == "true",
		FlagUnlicensed: meta["license.flag-unlicensed"] == "true",
	}
	for _, c := range splitCSV(meta["license.deny-classes"]) {
		p.DenyClasses = append(p.DenyClasses, liclib.Class(strings.ToLower(strings.TrimSpace(c))))
	}
	return p
}

func toLicenseIDs(ls []sbomlib.License) []liclib.LicenseID {
	out := make([]liclib.LicenseID, 0, len(ls))
	for _, l := range ls {
		out = append(out, liclib.LicenseID{ID: l.ID, Name: l.Name})
	}
	return out
}

func ruleForReason(r liclib.Reason) string {
	switch r {
	case liclib.ReasonDenied:
		return "DS-RAT-LIC-001"
	case liclib.ReasonNotAllowed:
		return "DS-RAT-LIC-002"
	case liclib.ReasonUnknown:
		return "DS-RAT-LIC-003"
	case liclib.ReasonUnlicensed:
		return "DS-RAT-LIC-004"
	default:
		return "DS-RAT-LIC-000"
	}
}

func titleForReason(v liclib.Verdict, c sbomlib.Component) string {
	switch v.Reason {
	case liclib.ReasonUnlicensed:
		return fmt.Sprintf("Component %q declares no license", c.Name)
	case liclib.ReasonUnknown:
		return fmt.Sprintf("Component %q has an unrecognized license %q", c.Name, v.License)
	case liclib.ReasonNotAllowed:
		return fmt.Sprintf("License %q of %q is not on the allowlist", v.License, c.Name)
	default:
		return fmt.Sprintf("Disallowed license %q in %q", v.License, c.Name)
	}
}

func describe(v liclib.Verdict, c sbomlib.Component) string {
	if v.Class != "" && v.Class != liclib.ClassUnknown {
		return fmt.Sprintf("%s %s is licensed %s (%s), which the configured license policy forbids for a distributed image.",
			c.Name, c.Version, v.License, v.Class)
	}
	return fmt.Sprintf("%s %s violates the configured license policy (%s).", c.Name, c.Version, v.Reason)
}

func remediation(v liclib.Verdict) string {
	switch v.Reason {
	case liclib.ReasonUnlicensed, liclib.ReasonUnknown:
		return "Confirm the component's license; if acceptable, add it to license.allow, otherwise replace the component."
	default:
		return "Replace the component with a permissively-licensed alternative, or waive with justification via the policy layer."
	}
}

func componentRef(c sbomlib.Component) string {
	if c.PURL != "" {
		return c.PURL
	}
	return c.Name + "@" + c.Version
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
