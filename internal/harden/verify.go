package harden

import (
	"sort"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Hardening verification framework ----------------------------------------
//
// Verification is a fixed list of checks, each a pure function of the normalised
// Workload. A check returns zero or more Results (a docker.sock mount and three
// sensitive bind mounts are four findings, not one), each tied to a Control that
// names the standard it enforces. The list order here is the canonical order;
// results are re-sorted by control id then resource so output is deterministic
// regardless of how many offenders a check found.

// Status is a check outcome.
type Status int

const (
	// StatusPass — the control is satisfied.
	StatusPass Status = iota
	// StatusFail — the control is violated (emitted as a finding at Control.Severity).
	StatusFail
	// StatusWarn — a weaker concern or a spec gap (emitted one severity lower).
	StatusWarn
	// StatusInfo — advisory (guidance, GPU present); emitted at INFO.
	StatusInfo
	// StatusNA — not applicable to this workload; never emitted.
	StatusNA
)

// Control describes one hardening rule and how a violation should surface.
type Control struct {
	// ID is the namespaced rule id, e.g. "DS-RAT-BOX-001".
	ID string
	// Title is the one-line human summary.
	Title string
	// Severity is the finding severity when the control FAILS.
	Severity engine.Severity
	// Remediation is the concrete fix.
	Remediation string
	// References cite the frameworks the control maps to (CIS/NIST/ATT&CK).
	References []string
}

// Result is one control's outcome for one workload.
type Result struct {
	Control  Control
	Status   Status
	Evidence string // why this outcome, in one human line
	Resource string // the concrete subject (workload, mount path, capability)
}

// Report is the full verification outcome for a workload.
type Report struct {
	Workload string
	Results  []Result
}

// checkFn is one verification check.
type checkFn func(w *Workload) []Result

// checks is the canonical, ordered list. Each function lives in a checks_*.go
// file grouped by concern; the order here is what a reader sees before sorting.
var checks = []checkFn{
	checkPrivileged,        // DS-RAT-BOX-001
	checkRunAsRoot,         // DS-RAT-BOX-002
	checkCapDropAll,        // DS-RAT-BOX-003
	checkDangerousCaps,     // DS-RAT-BOX-004
	checkNoNewPrivileges,   // DS-RAT-BOX-005
	checkReadOnlyRootFS,    // DS-RAT-BOX-006
	checkSeccomp,           // DS-RAT-BOX-007
	checkAppArmor,          // DS-RAT-BOX-008
	checkHostNamespaces,    // DS-RAT-BOX-009
	checkDockerSock,        // DS-RAT-BOX-010
	checkSensitiveMounts,   // DS-RAT-BOX-011
	checkMemoryLimit,       // DS-RAT-BOX-012
	checkPidsLimit,         // DS-RAT-BOX-013
	checkUserNamespace,     // DS-RAT-BOX-014
	checkSetuidNeutralized, // DS-RAT-BOX-015
	checkMaskedPaths,       // DS-RAT-BOX-016
	checkGPUDevices,        // DS-RAT-BOX-017
	checkGPUSharing,        // DS-RAT-BOX-018
}

// Verify runs every check against a workload and returns a deterministic report.
func Verify(w *Workload) *Report {
	var results []Result
	for _, c := range checks {
		results = append(results, c(w)...)
	}
	sort.SliceStable(results, func(i, j int) bool {
		if results[i].Control.ID != results[j].Control.ID {
			return results[i].Control.ID < results[j].Control.ID
		}
		return results[i].Resource < results[j].Resource
	})
	return &Report{Workload: w.Name, Results: results}
}

// Findings converts a report into engine findings, emitting everything except
// satisfied (Pass) and inapplicable (NA) results. Module is stamped by the
// caller's module name so the same core can back more than one frontend.
func (r *Report) Findings(module string) []engine.Finding {
	var out []engine.Finding
	for _, res := range r.Results {
		if res.Status == StatusPass || res.Status == StatusNA {
			continue
		}
		out = append(out, engine.Finding{
			RuleID:      res.Control.ID,
			Module:      module,
			Severity:    severityFor(res),
			Title:       res.Control.Title,
			Description: res.Evidence,
			Resource:    res.Resource,
			Remediation: res.Control.Remediation,
			References:  res.Control.References,
		})
	}
	return out
}

// Counts tallies results by status for summaries.
func (r *Report) Counts() map[Status]int {
	m := map[Status]int{}
	for _, res := range r.Results {
		m[res.Status]++
	}
	return m
}

// severityFor maps a result's status onto a finding severity: a failure emits at
// the control's severity, a warning one notch lower, and info at INFO.
func severityFor(res Result) engine.Severity {
	switch res.Status {
	case StatusFail:
		return res.Control.Severity
	case StatusWarn:
		return demote(res.Control.Severity)
	default:
		return engine.SeverityInfo
	}
}

// demote lowers a severity by one level, floored at Low (a warning is never Info
// unless the control itself is Info).
func demote(s engine.Severity) engine.Severity {
	switch s {
	case engine.SeverityCritical:
		return engine.SeverityHigh
	case engine.SeverityHigh:
		return engine.SeverityMedium
	case engine.SeverityMedium, engine.SeverityLow:
		return engine.SeverityLow
	default:
		return s
	}
}

// --- small result constructors ----------------------------------------------

// pass/fail/warn/info build a single Result for a control against a resource.
func pass(c Control, resource string) []Result {
	return []Result{{Control: c, Status: StatusPass, Resource: resource, Evidence: "satisfied"}}
}
func fail(c Control, resource, evidence string) []Result {
	return []Result{{Control: c, Status: StatusFail, Resource: resource, Evidence: evidence}}
}
func warn(c Control, resource, evidence string) []Result {
	return []Result{{Control: c, Status: StatusWarn, Resource: resource, Evidence: evidence}}
}
func info(c Control, resource, evidence string) []Result {
	return []Result{{Control: c, Status: StatusInfo, Resource: resource, Evidence: evidence}}
}
