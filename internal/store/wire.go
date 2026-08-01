package store

import (
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Persistence DTOs ----------------------------------------------------
//
// engine.Severity marshals to its string name ("HIGH") but has no matching
// UnmarshalJSON, so an engine.Report cannot round-trip through encoding/json on
// its own — reading it back fails to parse the severity string into the int
// type. Rather than depend on an engine change, the file backend serializes
// through these DTOs: severity travels as a string and is reconstructed with
// engine.ParseSeverity on load. This keeps the store self-contained and the
// shared engine untouched (see NOTES.md for the proposed engine.Severity
// UnmarshalJSON that would let these DTOs be retired).

type wireScan struct {
	ID         string            `json:"id"`
	Image      string            `json:"image"`
	Digest     string            `json:"digest,omitempty"`
	TargetType string            `json:"target_type,omitempty"`
	RecordedAt time.Time         `json:"recorded_at"`
	Labels     map[string]string `json:"labels,omitempty"`
	Report     *wireReport       `json:"report"`
	Components []Component       `json:"components,omitempty"`
}

type wireReport struct {
	Tool        string             `json:"tool"`
	TargetType  string             `json:"target_type"`
	Target      string             `json:"target"`
	GeneratedAt time.Time          `json:"generated_at"`
	Findings    []wireFinding      `json:"findings"`
	ModuleRuns  []engine.ModuleRun `json:"module_runs"`
}

type wireFinding struct {
	RuleID      string            `json:"rule_id"`
	Module      string            `json:"module"`
	Severity    string            `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Resource    string            `json:"resource,omitempty"`
	Location    *engine.Location  `json:"location,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	References  []string          `json:"references,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

func toWire(sc *Scan) *wireScan {
	w := &wireScan{
		ID: sc.ID, Image: sc.Image, Digest: sc.Digest, TargetType: sc.TargetType,
		RecordedAt: sc.RecordedAt, Labels: sc.Labels, Components: sc.Components,
	}
	if sc.Report != nil {
		wr := &wireReport{
			Tool: sc.Report.Tool, TargetType: string(sc.Report.TargetType), Target: sc.Report.Target,
			GeneratedAt: sc.Report.GeneratedAt, ModuleRuns: sc.Report.ModuleRuns,
		}
		for _, f := range sc.Report.Findings {
			wr.Findings = append(wr.Findings, wireFinding{
				RuleID: f.RuleID, Module: f.Module, Severity: f.Severity.String(), Title: f.Title,
				Description: f.Description, Resource: f.Resource, Location: f.Location,
				Remediation: f.Remediation, References: f.References, Metadata: f.Metadata,
			})
		}
		w.Report = wr
	}
	return w
}

func fromWire(w *wireScan) *Scan {
	sc := &Scan{
		ID: w.ID, Image: w.Image, Digest: w.Digest, TargetType: w.TargetType,
		RecordedAt: w.RecordedAt, Labels: w.Labels, Components: w.Components,
	}
	if w.Report != nil {
		r := &engine.Report{
			Tool: w.Report.Tool, TargetType: engine.TargetType(w.Report.TargetType), Target: w.Report.Target,
			GeneratedAt: w.Report.GeneratedAt, ModuleRuns: w.Report.ModuleRuns,
		}
		for _, f := range w.Report.Findings {
			r.Findings = append(r.Findings, engine.Finding{
				RuleID: f.RuleID, Module: f.Module, Severity: engine.ParseSeverity(f.Severity), Title: f.Title,
				Description: f.Description, Resource: f.Resource, Location: f.Location,
				Remediation: f.Remediation, References: f.References, Metadata: f.Metadata,
			})
		}
		sc.Report = r
	}
	return sc
}
