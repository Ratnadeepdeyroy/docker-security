package netpolicy

import (
	"sort"
	"strings"
)

// --- Auto-drafted policy change ------------------------------------------
//
// The AI-age "auto-drafted policy PR" thread: rather than hand an operator a
// wall of YAML, express the generated least-privilege policy as a *structured
// diff* against what is deployed today. An agent can read the added/removed
// entries, reason about each (the FQDN allowlist carries rationale), and open a
// change with a clear blast radius — added allows widen access, removed allows
// tighten it.

// PolicyDiff is the delta between a current and a generated allowlist. It is
// deliberately set-based (not a text diff) so it is stable and machine-appliable.
type PolicyDiff struct {
	Workload     string   `json:"workload,omitempty"`
	AddedFQDNs   []string `json:"added_fqdns,omitempty"`
	RemovedFQDNs []string `json:"removed_fqdns,omitempty"`
	AddedCIDRs   []string `json:"added_cidrs,omitempty"`
	RemovedCIDRs []string `json:"removed_cidrs,omitempty"`
}

// DiffAllowlists computes generated-minus-current: entries the generated policy
// adds (present in generated, absent in current) and removes (the reverse).
func DiffAllowlists(current, generated Allowlist) PolicyDiff {
	return PolicyDiff{
		AddedFQDNs:   difference(generated.FQDNs, current.FQDNs),
		RemovedFQDNs: difference(current.FQDNs, generated.FQDNs),
		AddedCIDRs:   difference(generated.CIDRs, current.CIDRs),
		RemovedCIDRs: difference(current.CIDRs, generated.CIDRs),
	}
}

// Empty reports whether the generated policy matches the current one exactly —
// the "nothing to do" signal an agent uses to skip opening a change.
func (d PolicyDiff) Empty() bool {
	return len(d.AddedFQDNs)+len(d.RemovedFQDNs)+len(d.AddedCIDRs)+len(d.RemovedCIDRs) == 0
}

// Render produces a human-readable, review-ready diff (+ widens, - tightens).
func (d PolicyDiff) Render() string {
	if d.Empty() {
		return "No changes: current policy already matches the generated least-privilege baseline.\n"
	}
	var b strings.Builder
	b.WriteString("Proposed egress-policy change (generated vs current):\n")
	writeSection(&b, "  + allow fqdn ", d.AddedFQDNs)
	writeSection(&b, "  - remove fqdn ", d.RemovedFQDNs)
	writeSection(&b, "  + allow cidr ", d.AddedCIDRs)
	writeSection(&b, "  - remove cidr ", d.RemovedCIDRs)
	return b.String()
}

func writeSection(b *strings.Builder, prefix string, items []string) {
	for _, it := range items {
		b.WriteString(prefix)
		b.WriteString(it)
		b.WriteByte('\n')
	}
}

// difference returns the sorted elements of a not present in b.
func difference(a, b []string) []string {
	inB := make(map[string]bool, len(b))
	for _, x := range b {
		inB[x] = true
	}
	var out []string
	seen := map[string]bool{}
	for _, x := range a {
		if !inB[x] && !seen[x] {
			out = append(out, x)
			seen[x] = true
		}
	}
	sort.Strings(out)
	return out
}
