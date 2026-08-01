package compliance

import (
	"sort"
	"strings"
)

// --- Compliance frameworks -------------------------------------------------

// Framework identifies a compliance regime a control can be mapped onto. The
// point of the abstraction is one scan → many audits: a single control failure
// simultaneously satisfies the evidence needs of CIS, NIST 800-190, DISA STIG,
// and the higher-level regimes those roll up into.
type Framework string

const (
	FrameworkCIS     Framework = "CIS"          // the native benchmark
	FrameworkNIST190 Framework = "NIST-800-190" // Application Container Security Guide
	FrameworkNIST53  Framework = "NIST-800-53"  // security & privacy controls
	FrameworkSTIG    Framework = "DISA-STIG"    // DoD Security Technical Implementation Guide
	FrameworkPCI     Framework = "PCI-DSS-4.0"  // payment card industry
	FrameworkNSACISA Framework = "NSA-CISA-K8s" // Kubernetes Hardening Guidance
)

// FrameworkRef is a single mapping: "this control corresponds to <ID> in
// <Framework>". A control may carry several. Kept as an explicit slice (not a
// map) so ordering is authored and deterministic.
type FrameworkRef struct {
	Framework Framework `json:"framework"`
	ID        string    `json:"id"`
}

// Ref is a terse constructor used when authoring benchmark catalogues in the
// dockerbench/kubebench packages.
func Ref(fw Framework, id string) FrameworkRef { return FrameworkRef{Framework: fw, ID: id} }

// hasNonCIS reports whether the control cites at least one framework beyond CIS
// itself. The definition-of-done requires every control to do so, and the
// benchmark self-tests assert it — this is the helper they use.
func hasNonCIS(refs []FrameworkRef) bool {
	for _, r := range refs {
		if r.Framework != FrameworkCIS && r.Framework != "" {
			return true
		}
	}
	return false
}

// References renders a control's framework mappings into the flat []string the
// engine.Finding.References field expects, prefixed with the native CIS control
// so downstream (SARIF helpUri, tables) always shows the benchmark id first.
// Output is deterministic: native CIS id, then authored order, de-duplicated.
func (c Control) References(benchmarkName string) []string {
	out := make([]string, 0, len(c.Frameworks)+1)
	seen := map[string]bool{}
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	add(benchmarkName + " " + c.ID)
	for _, r := range c.Frameworks {
		add(string(r.Framework) + " " + r.ID)
	}
	return out
}

// FrameworkCoverage summarizes, across a whole report, which frameworks are
// exercised and how many controls touch each. It powers the "one scan feeds
// many audits" story in the narrative and export. Keys are returned sorted by
// caller (see SortedFrameworks) so callers control iteration order.
func FrameworkCoverage(controls []Control) map[Framework]int {
	cov := map[Framework]int{}
	for _, c := range controls {
		cov[FrameworkCIS]++ // every control is a CIS control
		fwSeen := map[Framework]bool{FrameworkCIS: true}
		for _, r := range c.Frameworks {
			if r.Framework == "" || fwSeen[r.Framework] {
				continue
			}
			fwSeen[r.Framework] = true
			cov[r.Framework]++
		}
	}
	return cov
}

// SortedFrameworks returns the frameworks in a coverage map in a stable order.
func SortedFrameworks(cov map[Framework]int) []Framework {
	fws := make([]Framework, 0, len(cov))
	for fw := range cov {
		fws = append(fws, fw)
	}
	sort.Slice(fws, func(i, j int) bool { return string(fws[i]) < string(fws[j]) })
	return fws
}

// --- Control-ID ordering ---------------------------------------------------

// compareControlID orders dotted numeric control ids the way a human expects:
// "2.2" before "2.10", not lexicographically (where "2.10" < "2.2"). Segments
// that are not integers fall back to string comparison so mixed ids still sort
// stably. This is the single source of truth for deterministic result order.
func compareControlID(a, b string) bool {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		an, aok := atoi(as[i])
		bn, bok := atoi(bs[i])
		if aok && bok {
			if an != bn {
				return an < bn
			}
			continue
		}
		if as[i] != bs[i] {
			return as[i] < bs[i]
		}
	}
	return len(as) < len(bs)
}

// atoi parses a non-negative integer, reporting whether the whole string was
// numeric. It avoids strconv's error allocation on the hot sort path.
func atoi(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
	}
	return n, true
}
