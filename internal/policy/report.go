package policy

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Reading scan results as policy input ----------------------------------
//
// The CI gate evaluates policy over a scan Report produced by `dsecrat scan
// --format json`. engine.Severity marshals to a string ("HIGH") but has no
// matching UnmarshalJSON, so a Report cannot be decoded straight back into
// engine types. Rather than depend on an engine change, we decode into these
// mirror structs and translate severity ourselves — the policy engine stays
// self-sufficient. (A proposed engine.Severity.UnmarshalJSON is filed as a
// master action so reports round-trip natively later.)

// FindingJSON mirrors engine.Finding for decoding, with a string severity.
type FindingJSON struct {
	RuleID      string            `json:"rule_id"`
	Module      string            `json:"module"`
	Severity    string            `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Resource    string            `json:"resource,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	References  []string          `json:"references,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// toFinding translates the decoded finding into the engine model.
func (f FindingJSON) toFinding() engine.Finding {
	return engine.Finding{
		RuleID:      f.RuleID,
		Module:      f.Module,
		Severity:    engine.ParseSeverity(f.Severity),
		Title:       f.Title,
		Description: f.Description,
		Resource:    f.Resource,
		Remediation: f.Remediation,
		References:  f.References,
		Metadata:    f.Metadata,
	}
}

// ReportJSON is the subset of engine.Report the policy engine consumes.
type ReportJSON struct {
	TargetType string        `json:"target_type"`
	Target     string        `json:"target"`
	Findings   []FindingJSON `json:"findings"`
}

// LoadReport decodes a scan report JSON document.
func LoadReport(data []byte) (*ReportJSON, error) {
	var r ReportJSON
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parse scan report: %w", err)
	}
	return &r, nil
}

// EngineFindings returns the report's findings in the engine model.
func (r *ReportJSON) EngineFindings() []engine.Finding {
	out := make([]engine.Finding, len(r.Findings))
	for i, f := range r.Findings {
		out[i] = f.toFinding()
	}
	return out
}

// InferAttestation derives supply-chain state from a combined scan report
// without importing the verify module: it reads the verification verdict finding
// that the verify module emits (metadata verdict=PASSED and a comma-separated
// verified_levels). This lets a policy reference `signed` / `verified(...)` when
// the scan already ran verification, and otherwise reports nothing verified —
// the fail-closed default. The verify rule namespace ("DS-RAT-SUP-") is matched by
// prefix so a rename of a specific rule id does not silently break inference.
func InferAttestation(findings []engine.Finding) StaticAttestation {
	var att StaticAttestation
	for _, f := range findings {
		if f.Metadata == nil {
			continue
		}
		if !strings.HasPrefix(f.RuleID, "DS-RAT-SUP-") {
			continue
		}
		if f.Metadata["verdict"] == "PASSED" {
			att.IsSigned = true
		}
		if lv := f.Metadata["verified_levels"]; lv != "" {
			for _, p := range strings.Split(lv, ",") {
				if p = strings.TrimSpace(p); p != "" && !contains(att.Predicates, p) {
					att.Predicates = append(att.Predicates, p)
				}
			}
		}
	}
	return att
}
