// Package harden is the deterministic core for runtime confinement: it turns
// observed (or declared) workload behaviour into least-privilege seccomp and
// AppArmor profiles, and verifies a container/pod/OCI runtime spec against a
// hardening baseline (non-root, dropped caps, no-new-privileges, read-only
// rootfs, no host namespaces, no docker.sock, cgroup limits, GPU isolation, …).
//
// The package is deliberately OS-independent: profile generation and spec
// verification are pure data transforms over parsed JSON, so the whole thing
// builds and tests on any platform (the profiles it emits are consumed by a
// Linux kernel, but generating and checking them is not itself a Linux
// operation). It reads neither the wall clock nor a random source in its
// analysis path — callers inject any time needed (e.g. exception expiry), which
// is what keeps the golden tests byte-stable.
//
// Scope note (see IMPLEMENTATION_PLAN §3 non-goals): we generate profiles and
// verify posture; we do not implement a new sandbox runtime. Stronger runtimes
// (gVisor, Kata) are recommended, not built — see runtimeclass.go.
package harden

import (
	"sort"
	"strings"
)

// --- Capability normalisation ------------------------------------------------
//
// The same Linux capability is written a dozen ways in the wild: "CAP_SYS_ADMIN",
// "sys_admin", "SYS_ADMIN", "  cap_net_raw ". Every check and every generator
// compares capabilities, so they must all agree on one spelling. We normalise to
// the bare upper-case name without the CAP_ prefix ("SYS_ADMIN"), because that is
// how both the OCI runtime spec and the Kubernetes securityContext express them.

// NormalizeCap folds a capability into the canonical bare upper-case form:
// leading/trailing space trimmed, a "CAP_" prefix removed, upper-cased.
func NormalizeCap(c string) string {
	c = strings.ToUpper(strings.TrimSpace(c))
	c = strings.TrimPrefix(c, "CAP_")
	return c
}

// normalizeCaps normalises and de-duplicates a slice of capabilities, returning
// them sorted so callers (and golden files) see a stable order.
func normalizeCaps(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, c := range in {
		n := NormalizeCap(c)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// containsFold reports whether want (compared case-insensitively) is in list.
func containsFold(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

// dedupeSort returns the unique, sorted members of in (empty strings dropped).
func dedupeSort(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
