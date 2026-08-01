package harden

import "strings"

// --- RuntimeClass strength guidance ------------------------------------------
//
// Namespaces + cgroups + seccomp (runc) share the host kernel, so a kernel bug
// is a host compromise. For code you do not trust — third-party images,
// AI-generated code, anything an agent fetched and ran — a stronger runtime that
// does not expose the host kernel directly is the real mitigation. We recommend
// one by trust level; we do not implement it (that is an explicit non-goal).

// TrustLevel expresses how much the operator trusts the code in the workload.
type TrustLevel string

const (
	// TrustTrusted — first-party code, reviewed and built in-house.
	TrustTrusted TrustLevel = "trusted"
	// TrustInternal — internal but not individually reviewed (the default).
	TrustInternal TrustLevel = "internal"
	// TrustUntrusted — third-party or multi-tenant code.
	TrustUntrusted TrustLevel = "untrusted"
	// TrustHostile — attacker-controlled or unknown code (e.g. sandboxing
	// AI-agent-generated commands). Assume it will try to escape.
	TrustHostile TrustLevel = "hostile"
)

// ParseTrustLevel maps a string onto a TrustLevel, defaulting to internal.
func ParseTrustLevel(s string) TrustLevel {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trusted":
		return TrustTrusted
	case "untrusted":
		return TrustUntrusted
	case "hostile", "adversarial":
		return TrustHostile
	default:
		return TrustInternal
	}
}

// RuntimeRecommendation is the advice for a workload's isolation runtime.
type RuntimeRecommendation struct {
	Trust TrustLevel
	// Recommended is the runtime slug: "runc", "gvisor" (runsc), or "kata".
	Recommended string
	// Rationale is the one-line why.
	Rationale string
	// CurrentAdequate reports whether the workload's declared RuntimeClass already
	// meets or exceeds the recommendation.
	CurrentAdequate bool
	// Note carries any workload-specific caveat (e.g. GPU + gVisor limitations).
	Note string
}

// runtimeStrength ranks runtimes so we can compare "declared vs recommended".
var runtimeStrength = map[string]int{
	"": 0, "runc": 1, "crun": 1, "youki": 1,
	"gvisor": 2, "runsc": 2,
	"kata": 3, "kata-runtime": 3, "kata-qemu": 3, "firecracker": 3,
}

// RecommendRuntime returns runtime guidance for a workload at a trust level.
func RecommendRuntime(w *Workload, trust TrustLevel) RuntimeRecommendation {
	var rec RuntimeRecommendation
	rec.Trust = trust
	switch trust {
	case TrustHostile:
		rec.Recommended = "kata"
		rec.Rationale = "hostile code should run under hardware-virtualised isolation (Kata/Firecracker) so a kernel exploit does not reach the host kernel"
	case TrustUntrusted:
		rec.Recommended = "gvisor"
		rec.Rationale = "untrusted/multi-tenant code should run under a user-space kernel (gVisor/runsc), which intercepts syscalls and shrinks the host kernel attack surface"
	default:
		rec.Recommended = "runc"
		rec.Rationale = "trusted first-party code can run under runc provided the hardening controls in this report pass"
	}

	declared := strings.ToLower(strings.TrimSpace(w.RuntimeClass))
	rec.CurrentAdequate = runtimeStrength[declared] >= runtimeStrength[rec.Recommended]

	// GPU workloads constrain the choice: gVisor's GPU support is limited/
	// experimental, and passthrough under Kata needs explicit device wiring.
	if detectGPU(w).present && (rec.Recommended == "gvisor" || rec.Recommended == "kata") {
		rec.Note = "this workload uses a GPU: verify accelerator support under the recommended runtime (gVisor GPU support is limited; Kata needs explicit device passthrough) before switching"
	}
	return rec
}
