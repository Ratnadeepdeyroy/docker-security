// Package rbac analyzes Kubernetes and Docker identity configuration for
// over-privilege and privilege-escalation paths. It is a pure library: given a
// set of recorded API objects (RBAC roles/bindings, service accounts, pods) as
// JSON, plus an optional Docker-host descriptor, it builds a permission graph,
// answers reverse "who-can-X-on-Y" queries, and emits deterministic Risk records
// for the well-known escalation primitives (wildcards, escalate/bind/impersonate,
// secret reads, token minting, CSR signing, pod exec, workload creation, node
// proxy, cluster-admin, dangling bindings, default-SA usage, docker-group and
// socket exposure). It also reconstructs concrete pod → cluster-admin/node-root
// escalation chains and can generate least-privilege roles from observed usage.
//
// The package never reads the wall clock or a random source: everything that
// needs "now" takes it through Options, so the same input always yields the same
// output (the golden test depends on this). The engine module in
// internal/modules/rbac projects these Risk values onto engine.Finding; the
// `dsecrat rbac` command renders them for humans.
package rbac

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Options -------------------------------------------------------------

// Options tunes an analysis run. The zero value is a safe, deterministic default
// (NHI off, a fixed epoch "now", 90-day dormancy, blast-radius threshold 3), so
// callers can pass Options{} and get reproducible results.
type Options struct {
	// EnableNHI turns on the non-human-identity risk graph (AI-age feature). Off
	// by default so the deterministic core never depends on the optional layer.
	EnableNHI bool
	// Now is the reference time for dormancy calculations. Zero means a fixed
	// epoch, keeping analysis deterministic when no clock is injected.
	Now time.Time
	// DormantAfter is how long since last use before an identity is "dormant".
	DormantAfter time.Duration
	// BroadThreshold is the reachable-principal count above which a non-human
	// identity is considered over-broad even without reaching a terminal target.
	BroadThreshold int
}

func (o Options) now() time.Time {
	if o.Now.IsZero() {
		// A fixed, explicit epoch — never time.Now() — so results are stable.
		return time.Unix(0, 0).UTC()
	}
	return o.Now
}

func (o Options) dormantAfter() time.Duration {
	if o.DormantAfter <= 0 {
		return 90 * 24 * time.Hour
	}
	return o.DormantAfter
}

func (o Options) broadThreshold() int {
	if o.BroadThreshold <= 0 {
		return 3
	}
	return o.BroadThreshold
}

// --- Report --------------------------------------------------------------

// Report is the full result of an analysis: the ordered risks plus the resolved
// graph (so callers can run additional who-can queries). Counts are precomputed
// for quick summaries.
type Report struct {
	Risks  []Risk
	Graph  *Graph
	Counts map[engine.Severity]int
}

// Analyze runs every enabled check over a parsed cluster and returns an ordered
// Report. It is the single analysis entry point used by the module and the CLI.
func Analyze(c *Cluster, opts Options) *Report {
	g := buildGraph(c)
	risks := checkAll(c, g, opts)
	counts := map[engine.Severity]int{}
	for _, r := range risks {
		counts[r.Severity]++
	}
	return &Report{Risks: risks, Graph: g, Counts: counts}
}

// AnalyzeBytes is a convenience wrapper: parse JSON then analyze.
func AnalyzeBytes(data []byte, opts Options) (*Report, error) {
	c, err := LoadBytes(data)
	if err != nil {
		return nil, err
	}
	return Analyze(c, opts), nil
}

// AnalyzePath is a convenience wrapper: parse a file/dir then analyze.
func AnalyzePath(path string, opts Options) (*Report, error) {
	c, err := LoadPath(path)
	if err != nil {
		return nil, err
	}
	return Analyze(c, opts), nil
}

// Highest returns the most severe risk level present, or SeverityUnknown when
// the report is clean. Frontends use it for exit codes and gating.
func (r *Report) Highest() engine.Severity {
	high := engine.SeverityUnknown
	for _, rk := range r.Risks {
		if rk.Severity > high {
			high = rk.Severity
		}
	}
	return high
}

// --- Human rendering (for `dsecrat rbac`) -----------------------------------

// Text renders the report as a stable, human-readable summary. It is
// deterministic (risks are already sorted) and safe to snapshot in a golden test.
func (r *Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "RBAC/identity risk report: %d finding(s)\n", len(r.Risks))
	for _, sev := range []engine.Severity{engine.SeverityCritical, engine.SeverityHigh, engine.SeverityMedium, engine.SeverityLow, engine.SeverityInfo} {
		if n := r.Counts[sev]; n > 0 {
			fmt.Fprintf(&b, "  %-8s %d\n", sev.String(), n)
		}
	}
	b.WriteString("\n")
	for _, rk := range r.Risks {
		fmt.Fprintf(&b, "[%s] %s: %s\n", rk.Severity.String(), rk.RuleID, rk.Title)
		if rk.Description != "" {
			fmt.Fprintf(&b, "    %s\n", rk.Description)
		}
		if len(rk.Path) > 0 {
			fmt.Fprintf(&b, "    path: %s\n", strings.Join(rk.Path, " -> "))
		}
	}
	return b.String()
}

// --- Reverse-query convenience -------------------------------------------

// WhoCan is a passthrough to the graph's reverse query, letting CLI/agent callers
// ask "who can <verb> <resource> in <namespace>" against an analyzed report.
func (r *Report) WhoCan(verb, apiGroup, resource, namespace string) []Subject {
	return r.Graph.WhoCan(verb, apiGroup, resource, namespace)
}

// sortedSubjectKeys is exposed for reporting/tests: the distinct subjects seen.
func (r *Report) sortedSubjectKeys() []string {
	ks := r.Graph.subjectKeys()
	sort.Strings(ks)
	return ks
}
