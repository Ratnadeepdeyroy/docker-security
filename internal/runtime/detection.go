package runtime

import (
	"fmt"
	"sort"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Detection: the detector's output ------------------------------------

// Detection is a single fired rule: what happened, how bad it is, where in the
// ATT&CK matrix it sits, and the event that triggered it. It is a runtime-domain
// value; the engine module projects it into engine.Finding for the unified
// report, but the daemon and forensic bundle keep the richer form.
type Detection struct {
	// RuleID is the namespaced rule identifier (DS-RAT-RT-NNN).
	RuleID   string          `json:"rule_id"`
	Severity engine.Severity `json:"severity"`
	Title    string          `json:"title"`
	// Message is the human, incident-time explanation of this specific event
	// ("nginx (pid 812) spawned /bin/sh with a tty").
	Message string `json:"message"`
	// Technique is the ATT&CK mapping.
	Technique Technique `json:"technique"`
	// Seq/Time echo the triggering event for ordering and correlation.
	Seq          uint64 `json:"seq"`
	TimeUnixNano int64  `json:"time_unix_nano,omitempty"`
	// Container and Process snapshot the actor at detection time.
	Container   ContainerInfo `json:"container"`
	Process     ProcessInfo   `json:"process"`
	Remediation string        `json:"remediation,omitempty"`
	References  []string      `json:"references,omitempty"`
	// Metadata carries rule-specific structured detail (matched path, remote
	// endpoint, drifted binary) for machine consumers and forensics.
	Metadata map[string]string `json:"metadata,omitempty"`
	// Trigger is the full triggering event, retained for the forensic bundle.
	// It is omitted from findings but kept in the daemon/forensics path.
	Trigger *Event `json:"trigger,omitempty"`
}

// ToFinding projects a Detection into the engine's Finding model. The module
// uses this so runtime detections appear in the same report as static findings.
// The triggering event is dropped here (findings are summaries); the full event
// lives in the forensic bundle.
func (d Detection) ToFinding(module string) engine.Finding {
	meta := map[string]string{
		"attack_technique": d.Technique.ID,
		"attack_tactic":    d.Technique.Tactic,
		"pid":              fmt.Sprintf("%d", d.Process.PID),
		"event_seq":        fmt.Sprintf("%d", d.Seq),
	}
	for k, v := range d.Metadata {
		meta[k] = v
	}
	resource := d.Container.Name
	if resource == "" {
		resource = d.Container.ID
	}
	refs := d.References
	if d.Technique.URL != "" {
		refs = append([]string{d.Technique.URL}, refs...)
	}
	return engine.Finding{
		RuleID:      d.RuleID,
		Module:      module,
		Severity:    d.Severity,
		Title:       d.Title,
		Description: d.Message,
		Resource:    resource,
		Remediation: d.Remediation,
		References:  refs,
		Metadata:    meta,
	}
}

// SortDetections orders detections deterministically: by event sequence, then
// rule id. Two runs over the same stream therefore emit an identical list.
func SortDetections(ds []Detection) {
	sort.SliceStable(ds, func(i, j int) bool {
		if ds[i].Seq != ds[j].Seq {
			return ds[i].Seq < ds[j].Seq
		}
		return ds[i].RuleID < ds[j].RuleID
	})
}
