// Package policy is the engine module and command surface for policy-as-code.
// It is the CI/shift-left half of Phase 4: it evaluates a committed policy
// (internal/policy) against a scan Report and projects the allow/warn/deny
// outcome into the unified Finding model with the DS-RAT-POL- rule namespace, so a
// pipeline can gate on `dsecrat scan` output the same way `dsecrat policy eval` does.
//
// The heavy lifting — the expression language, decision logic, waivers, and the
// explainable-deny feature — lives in internal/policy. This package resolves
// inputs from the target's Metadata (keeping Analyze a pure function of its
// inputs), runs the evaluation, and formats findings. Like the verify module it
// fails safe: with no policy configured it reports "not configured" (INFO) and
// gates nothing — never a false pass.
package policy

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/policy"
)

const moduleName = "policy"

// Reserved DS-RAT-POL- rule ids for the module's own diagnostics. Individual policy
// rules are carried in finding metadata (rule=<id>) rather than minting a new
// DS-RAT-POL number per authored rule.
const (
	ruleVerdict       = "DS-RAT-POL-000" // overall decision summary
	ruleNotConfigured = "DS-RAT-POL-001" // no policy supplied
	ruleLoadError     = "DS-RAT-POL-002" // policy failed to load/compile
	ruleViolation     = "DS-RAT-POL-100" // a deny rule blocked
	ruleWarning       = "DS-RAT-POL-101" // a warn rule fired
	ruleWaived        = "DS-RAT-POL-110" // a firing was suppressed by a waiver
)

// Module is the policy-as-code gate capability (CAPABILITY_SPEC domain 8).
type Module struct{}

// New returns a policy module.
func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "Gate scan results against policy-as-code rules (allow/warn/deny, waivers) (domain 8)"
}
func (m *Module) Domains() []string { return []string{"8"} }

// Supports gates the artifact-level targets where a policy decision is
// meaningful. Dockerfiles and containers are handled by their own modules; a
// policy run over them would have no report to judge.
func (m *Module) Supports(t engine.TargetType) bool {
	return t == engine.TargetImage || t == engine.TargetFilesystem || t == engine.TargetRegistry
}

// Analyze evaluates a policy against the target. Configuration travels via the
// target's Metadata so the module stays deterministic:
//
//	policy.file      path to the policy document JSON (required to gate anything)
//	policy.report    path to a `dsecrat scan --format json` report to judge
//	policy.now       RFC3339 evaluation time for waiver expiry (deterministic)
//	policy.explain   "true" to attach an agent-consumable explanation (off by default)
//	policy.signed    "true" to assert the image is signed (else inferred from report)
//	policy.verified  comma-separated verified predicate-type URIs
//	policy.registry  image registry (else derived from the target reference)
//	policy.repository/policy.tag/policy.digest  image identity overrides
//
// With no policy.file it reports "not configured" (INFO) and gates nothing.
func (m *Module) Analyze(_ context.Context, t *engine.Target) ([]engine.Finding, error) {
	md := t.Metadata
	if md == nil {
		md = map[string]string{}
	}

	policyPath := md["policy.file"]
	if policyPath == "" {
		return []engine.Finding{diag(ruleNotConfigured, engine.SeverityInfo,
			"Policy gate not configured",
			"No policy.file was provided for this target; skipping policy evaluation.",
			t.Location, "Provide a policy via policy.file metadata, or run `dsecrat policy eval`.")}, nil
	}

	eng, err := loadEngine(policyPath)
	if err != nil {
		// A policy we cannot load is a broken gate. Surface it as a high finding
		// rather than passing silently.
		return []engine.Finding{diag(ruleLoadError, engine.SeverityHigh,
			"Policy failed to load",
			err.Error(), t.Location,
			"Fix the policy document so it parses and compiles; run `dsecrat policy test` in CI.")}, nil
	}

	in, err := buildInput(md, t)
	if err != nil {
		return nil, err
	}

	res := eng.Evaluate(in, evalClock(md))

	explain := md["policy.explain"] == "true"
	var ex *policy.Explanation
	if explain {
		ex = eng.Explain(res, in)
	}
	return projectFindings(res, ex, t.Location), nil
}

// loadEngine reads and compiles a policy document.
func loadEngine(path string) (*policy.Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy %q: %w", path, err)
	}
	eng, err := policy.CompileBytes(data)
	if err != nil {
		return nil, err
	}
	return eng, nil
}

// evalClock resolves the injected evaluation time. Analysis never reads the wall
// clock; an absent policy.now yields the zero time, under which no waiver is
// honored (see policy.Waiver.active) — the deterministic, fail-closed default.
func evalClock(md map[string]string) time.Time {
	if s := md["policy.now"]; s != "" {
		if ts, err := time.Parse(time.RFC3339, s); err == nil {
			return ts
		}
	}
	return time.Time{}
}

// buildInput assembles the policy Input from a scan report (when provided) and
// metadata hints about image identity and attestation state.
func buildInput(md map[string]string, t *engine.Target) (*policy.Input, error) {
	in := &policy.Input{Image: imageFromMetadata(md, t)}

	if rp := md["policy.report"]; rp != "" {
		data, err := os.ReadFile(rp)
		if err != nil {
			return nil, fmt.Errorf("read policy.report %q: %w", rp, err)
		}
		rep, err := policy.LoadReport(data)
		if err != nil {
			return nil, err
		}
		in.Findings = rep.EngineFindings()
		in.Licenses = licensesFromFindings(in.Findings)
	}

	in.Attest = attestationFromMetadata(md, in.Findings)
	return in, nil
}

// imageFromMetadata derives image identity from explicit hints, falling back to
// the target reference for the full reference string.
func imageFromMetadata(md map[string]string, t *engine.Target) policy.Image {
	return policy.Image{
		Reference:  first(md["policy.image_ref"], t.Location),
		Registry:   md["policy.registry"],
		Repository: md["policy.repository"],
		Tag:        md["policy.tag"],
		Digest:     md["policy.digest"],
	}
}

// attestationFromMetadata prefers explicit signed/verified hints; absent those,
// it infers state from the scan report's verification verdict (decoupled from
// the verify module — see policy.InferAttestation).
func attestationFromMetadata(md map[string]string, findings []engine.Finding) policy.AttestationState {
	_, haveSigned := md["policy.signed"]
	_, haveVerified := md["policy.verified"]
	if !haveSigned && !haveVerified {
		return policy.InferAttestation(findings)
	}
	att := policy.StaticAttestation{IsSigned: md["policy.signed"] == "true"}
	for _, p := range strings.Split(md["policy.verified"], ",") {
		if p = strings.TrimSpace(p); p != "" {
			att.Predicates = append(att.Predicates, p)
		}
	}
	return att
}

// licensesFromFindings collects SPDX license ids that SBOM/license findings
// carry in their metadata, so a policy can reference has_license(...).
func licensesFromFindings(fs []engine.Finding) []string {
	var out []string
	seen := map[string]bool{}
	for _, f := range fs {
		if lic := f.Metadata["license"]; lic != "" && !seen[lic] {
			seen[lic] = true
			out = append(out, lic)
		}
	}
	return out
}

func first(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
