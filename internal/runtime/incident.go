package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// This file builds the agent-driven-incident-response feature: it turns a raw
// Detection into a structured Incident carrying a suggested containment
// playbook — ordered, machine-consumable steps an SRE or an automation agent can
// execute, each with an explicit guardrail. The deterministic detection is the
// source of truth; this is an enrichment layer that makes a finding *actionable*
// rather than just informative, and is exactly the shape an MCP tool would hand
// an agent. It is produced only on request (daemon --incidents / module opt-in),
// never by default, so it can never gate correctness.
//
// Incident IDs are a stable hash of the detection, so the same detection always
// yields the same incident id — de-duplication and correlation for free, with no
// clock or counter.

// Incident is an actionable, structured view of a detection.
type Incident struct {
	ID        string          `json:"id"`
	RuleID    string          `json:"rule_id"`
	Title     string          `json:"title"`
	Severity  engine.Severity `json:"severity"`
	Technique Technique       `json:"technique"`
	Summary   string          `json:"summary"`
	Container ContainerInfo   `json:"container"`
	// Playbook is the ordered set of suggested containment steps.
	Playbook []PlaybookStep `json:"playbook"`
	// Automatable reports whether every step is safe to automate under its
	// guardrails — an agent can act autonomously only when this is true.
	Automatable bool     `json:"automatable"`
	References  []string `json:"references,omitempty"`
}

// PlaybookStep is one containment action. Guardrail states the precondition or
// safety check that must hold before the step runs — the difference between a
// helpful automation and a self-inflicted outage.
type PlaybookStep struct {
	Order       int    `json:"order"`
	Action      string `json:"action"`
	Command     string `json:"command,omitempty"`
	Guardrail   string `json:"guardrail"`
	Automatable bool   `json:"automatable"`
}

// BuildIncident enriches a detection into an incident with a playbook chosen by
// the detection class. Steps escalate from evidence-preserving (always safe) to
// containment (guarded).
func BuildIncident(d Detection) *Incident {
	inc := &Incident{
		ID:         incidentID(d),
		RuleID:     d.RuleID,
		Title:      d.Title,
		Severity:   d.Severity,
		Technique:  d.Technique,
		Summary:    d.Message,
		Container:  d.Container,
		References: d.References,
	}
	inc.Playbook = playbookFor(d)
	inc.Automatable = allAutomatable(inc.Playbook)
	return inc
}

// incidentID is a deterministic id: a short hash of the identifying fields of a
// detection. Same detection → same id, across runs and machines.
func incidentID(d Detection) string {
	h := sha256.New()
	h.Write([]byte(d.RuleID))
	h.Write([]byte{0})
	h.Write([]byte(containerKey(d.Container)))
	h.Write([]byte{0})
	h.Write([]byte(itoa(int(d.Seq))))
	return "INC-" + hex.EncodeToString(h.Sum(nil))[:12]
}

// playbookFor returns containment steps for a detection. Step 1 is always
// evidence preservation (safe to automate); later steps are containment gated on
// a guardrail. Escape/kernel incidents extend to node-level containment.
func playbookFor(d Detection) []PlaybookStep {
	steps := []PlaybookStep{
		{
			Order:       1,
			Action:      "Capture a forensic bundle for the offending container (process tree + event window).",
			Command:     "dsecrat-runtime replay --forensics-dir ./evidence <capture>",
			Guardrail:   "Read-only; always safe.",
			Automatable: true,
		},
	}
	switch d.RuleID {
	case "DS-RAT-RT-003", "DS-RAT-RT-008": // escape / kernel abuse → host is at risk
		steps = append(steps,
			PlaybookStep{2, "Cordon the node so no new workloads schedule onto it.", "kubectl cordon <node>", "Confirm the node hosts no single-replica critical workloads first.", false},
			PlaybookStep{3, "Quarantine the pod: cut its network and pause it for live analysis.", "kubectl label pod <pod> quarantine=true  # triggers deny-all NetworkPolicy", "Requires a pre-provisioned quarantine NetworkPolicy.", true},
			PlaybookStep{4, "Snapshot the node for offline forensics before remediation.", "", "Storage/volume snapshot permissions required.", false},
		)
	case "DS-RAT-RT-005": // credential theft → rotate
		steps = append(steps,
			PlaybookStep{2, "Rotate any credential the workload could reach (SA token, cloud keys).", "kubectl delete secret <sa-token>  # forces reissue", "Confirm dependent workloads tolerate rotation.", false},
			PlaybookStep{3, "Block IMDS egress from the pod and enforce IMDSv2 hop-limit 1.", "", "Requires NetworkPolicy / IMDSv2 support.", true},
		)
	default: // process/file/network → contain the workload
		steps = append(steps,
			PlaybookStep{2, "Isolate the container's network (deny-all egress) pending triage.", "kubectl label pod <pod> quarantine=true", "Requires a pre-provisioned quarantine NetworkPolicy.", true},
			PlaybookStep{3, "If confirmed malicious, terminate the offending process / redeploy from a trusted image.", "", "Human confirmation recommended for production.", false},
		)
	}
	return steps
}

func allAutomatable(steps []PlaybookStep) bool {
	for _, s := range steps {
		if !s.Automatable {
			return false
		}
	}
	return true
}
