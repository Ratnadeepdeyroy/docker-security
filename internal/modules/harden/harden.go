// Package harden is the capability module that surfaces runtime-confinement
// findings through the engine. It is a thin adapter: the deterministic work —
// parsing a container/pod/OCI spec, verifying it against the hardening baseline,
// generating least-privilege profiles — lives in internal/harden. This package
// maps that library onto the Module contract and the `dsecrat harden` command.
//
// The module verifies a container/pod/OCI-runtime spec (TargetContainer). Its
// core checks are always-on and deterministic; the agent-appliable hardening
// bundle (the AI-age feature) stays OFF unless a caller opts in, so correctness
// never depends on it.
package harden

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	hardenlib "github.com/Ratnadeepdeyroy/docker-security/internal/harden"
)

const moduleName = "harden"

// maxSpecBytes bounds a spec read from disk so a hostile file cannot exhaust
// memory. Container/pod specs are small; this is generous.
const maxSpecBytes = 8 << 20

// Module verifies workload isolation posture and (opt-in) emits an
// agent-appliable hardening bundle.
type Module struct {
	// bundle enables the DS-RAT-BOX-900 agent-appliable hardening bundle. Off by
	// default: it is an enrichment, and we never gate correctness on it.
	bundle bool
}

// Option configures a Module at construction.
type Option func(*Module)

// WithHardeningBundle turns on the off-by-default agent-appliable hardening
// bundle (securityContext patch + generated profiles + expiry-bound waivers).
func WithHardeningBundle() Option {
	return func(m *Module) { m.bundle = true }
}

// New returns a harden module. With no options it is the deterministic baseline
// verifier with the bundle feature off.
func New(opts ...Option) *Module {
	m := &Module{}
	for _, o := range opts {
		o(m)
	}
	return m
}

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "Runtime confinement: verify container/pod/OCI hardening posture and generate least-privilege profiles (domain 12)"
}

// Domains covers CAPABILITY_SPEC domain 12 (sandboxing & isolation).
func (m *Module) Domains() []string { return []string{"12"} }

// Supports handles container targets: the spec/runtime config of a workload.
func (m *Module) Supports(t engine.TargetType) bool { return t == engine.TargetContainer }

// Analyze parses the target's spec, verifies every container it describes, and
// projects the results into findings. A Kubernetes Pod yields one workload per
// container. Input that is valid JSON but not a spec we recognise yields no
// findings (the module stays quiet rather than erroring), mirroring the other
// spec-driven modules.
func (m *Module) Analyze(_ context.Context, t *engine.Target) ([]engine.Finding, error) {
	data, err := readSpec(t)
	if err != nil {
		return nil, fmt.Errorf("harden: %w", err)
	}
	workloads, err := hardenlib.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("harden: %q: %w", t.Location, err)
	}
	if len(workloads) == 0 {
		return nil, nil // not a spec we handle; say nothing
	}

	trust := hardenlib.TrustInternal
	if t.Metadata != nil {
		if v := t.Metadata["harden.trust"]; v != "" {
			trust = hardenlib.ParseTrustLevel(v)
		}
	}

	var findings []engine.Finding
	for i := range workloads {
		w := &workloads[i]
		rep := hardenlib.Verify(w)
		findings = append(findings, rep.Findings(moduleName)...)
		findings = append(findings, runtimeGuidance(w, trust))
		if m.bundle {
			findings = append(findings, bundleFinding(w, rep, t))
		}
	}

	sortFindings(findings)
	return findings, nil
}

// runtimeGuidance emits the RuntimeClass strength recommendation as an INFO
// finding so it rides alongside the hardening results.
func runtimeGuidance(w *hardenlib.Workload, trust hardenlib.TrustLevel) engine.Finding {
	rec := hardenlib.RecommendRuntime(w, trust)
	desc := fmt.Sprintf("For %s workloads, recommended runtime: %s. %s.", rec.Trust, rec.Recommended, rec.Rationale)
	if !rec.CurrentAdequate && w.RuntimeClass != "" {
		desc += fmt.Sprintf(" Declared runtimeClass %q is weaker than recommended.", w.RuntimeClass)
	}
	if rec.Note != "" {
		desc += " Note: " + rec.Note
	}
	md := map[string]string{"trust": string(rec.Trust), "recommended": rec.Recommended}
	if w.RuntimeClass != "" {
		md["declared"] = w.RuntimeClass
	}
	return engine.Finding{
		RuleID:      "DS-RAT-BOX-020",
		Module:      moduleName,
		Severity:    engine.SeverityInfo,
		Title:       "RuntimeClass strength guidance",
		Description: desc,
		Resource:    w.Name,
		Remediation: "Set the workload's runtimeClass to at least the recommended runtime for its trust level.",
		References:  []string{"NIST SP 800-190 4.5.4", "MITRE ATT&CK T1611"},
		Metadata:    md,
	}
}

// sortFindings gives the module a stable order (rule id, then resource) so the
// golden test can pin output regardless of workload/check iteration order.
func sortFindings(fs []engine.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].RuleID != fs[j].RuleID {
			return fs[i].RuleID < fs[j].RuleID
		}
		return fs[i].Resource < fs[j].Resource
	})
}

// readSpec returns the spec bytes from inlined Content when present, else from
// the target location on disk (size-capped).
func readSpec(t *engine.Target) ([]byte, error) {
	if len(t.Content) > 0 {
		return t.Content, nil
	}
	if t.Location == "" {
		return nil, fmt.Errorf("no spec content or location")
	}
	f, err := os.Open(t.Location)
	if err != nil {
		return nil, fmt.Errorf("open spec %q: %w", t.Location, err)
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxSpecBytes))
}
