package harden

import (
	"encoding/json"
	"fmt"
	"strings"
)

// --- The normalised workload model -------------------------------------------
//
// Verification reasons over one shape, Workload, no matter where the spec came
// from. Two real, kernel-facing formats are normalised into it: an OCI runtime
// config.json (what runc actually consumes) and a Kubernetes Pod (what most
// people write). Parse auto-detects which and returns one Workload per container.
// Keeping the checks decoupled from the source format means adding a third input
// (Nomad, docker inspect, …) is a new parser, not new checks.

// Mount is a filesystem mount into the container.
type Mount struct {
	// Source is the host path (or volume) backing the mount; empty for tmpfs.
	Source string
	// Destination is the in-container path.
	Destination string
	// ReadOnly is true when the mount cannot be written.
	ReadOnly bool
	// Type is the mount type ("bind", "tmpfs", …) when known.
	Type string
}

// Device is a host device exposed to the container. Used chiefly for GPU checks.
type Device struct {
	Path string
	Type string
}

// SeccompMode classifies the workload's seccomp posture in a source-agnostic way.
type SeccompMode string

const (
	// SeccompUnset means no seccomp profile is configured (runtime may still
	// apply its default, but the spec does not assert one).
	SeccompUnset SeccompMode = ""
	// SeccompUnconfined explicitly disables seccomp — the dangerous case.
	SeccompUnconfined SeccompMode = "unconfined"
	// SeccompRuntimeDefault applies the runtime's default profile.
	SeccompRuntimeDefault SeccompMode = "runtime-default"
	// SeccompLocalhost / SeccompCustom applies a specific profile.
	SeccompLocalhost SeccompMode = "localhost"
	SeccompCustom    SeccompMode = "custom"
)

// Workload is the normalised isolation posture of a single container. Every
// verification check reads from here and nowhere else.
type Workload struct {
	Name  string // container name or workload label
	Image string

	// Privilege posture.
	Privileged               bool
	RunAsUser                *int64 // nil = unset; 0 = root
	RunAsNonRoot             *bool
	AllowPrivilegeEscalation *bool // Kubernetes; maps to no-new-privileges
	NoNewPrivileges          bool  // OCI process.noNewPrivileges
	ReadOnlyRootFS           bool

	// Capabilities, normalised bare upper-case (no CAP_ prefix).
	CapAdd  []string
	CapDrop []string

	// Confinement profiles.
	Seccomp        SeccompMode
	SeccompProfile string // profile name/path when Localhost/Custom
	AppArmor       string // "", "unconfined", "runtime/default", or a profile name

	// Namespace sharing with the host.
	HostPID     bool
	HostIPC     bool
	HostNetwork bool
	// HostUsers is true when the container shares the host user namespace (i.e.
	// user-namespace remapping is NOT in effect). Kubernetes hostUsers=true or an
	// OCI spec with no "user" namespace both set this.
	HostUsers bool

	Mounts  []Mount
	Devices []Device

	// Cgroup limits (0 = unlimited/unset).
	MemoryLimitBytes int64
	PidsLimit        int64

	// OCI procfs hardening: the masked and read-only kernel paths.
	MaskedPaths   []string
	ReadonlyPaths []string

	// Env is a small, normalised view of environment variables that matter to
	// isolation (currently NVIDIA_VISIBLE_DEVICES for GPU scoping).
	Env map[string]string

	// RuntimeClass is the requested runtime ("runc", "gvisor"/"runsc", "kata", …)
	// when the source declares one; drives RuntimeClass guidance.
	RuntimeClass string

	// Source records which parser produced this Workload ("oci" or "kubernetes"),
	// purely for diagnostics.
	Source string
}

// maxSpecBytes bounds a spec read so a hostile document cannot exhaust memory.
const maxSpecBytes = 8 << 20

// Parse auto-detects the spec format and returns one Workload per container.
// An OCI runtime spec yields exactly one; a Kubernetes Pod yields one per
// container (init containers included). Unrecognised-but-valid JSON yields a nil
// slice and no error, so a caller scanning arbitrary files stays quiet on
// non-specs (mirrors how the other benchmark modules degrade).
func Parse(data []byte) ([]Workload, error) {
	if len(data) > maxSpecBytes {
		return nil, fmt.Errorf("spec too large: %d bytes (max %d)", len(data), maxSpecBytes)
	}
	// A cheap structural probe decides the parser without fully unmarshalling
	// twice. We only need to see which discriminating keys are present.
	var probe struct {
		OCIVersion string          `json:"ociVersion"`
		Process    json.RawMessage `json:"process"`
		Root       json.RawMessage `json:"root"`
		Kind       string          `json:"kind"`
		Spec       json.RawMessage `json:"spec"`
		Containers json.RawMessage `json:"containers"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("parse spec: %w", err)
	}

	switch {
	case probe.OCIVersion != "" || (probe.Process != nil && probe.Root != nil):
		w, err := parseOCISpec(data)
		if err != nil {
			return nil, err
		}
		return []Workload{*w}, nil
	case strings.EqualFold(probe.Kind, "pod") || probe.Spec != nil || probe.Containers != nil:
		return parseKubePod(data)
	default:
		return nil, nil // valid JSON, but not a spec we recognise
	}
}

// --- shared helpers for the parsers ------------------------------------------

// isRootUID reports whether a user string/uid denotes root. Empty is treated as
// "unknown", not root, so a missing user does not itself trigger the root check
// (a separate signal — RunAsUser/RunAsNonRoot — governs that).
func isRootUID(user string) bool {
	user = strings.TrimSpace(user)
	if user == "" {
		return false
	}
	// "0", "0:0", "root", "root:root"
	head := user
	if i := strings.IndexAny(user, ":/"); i >= 0 {
		head = user[:i]
	}
	return head == "0" || strings.EqualFold(head, "root")
}

func boolPtr(b bool) *bool    { return &b }
func int64Ptr(i int64) *int64 { return &i }
