// Package runtime is the offline core of the runtime threat-detection sensor
// (dsecrat-runtime). It defines the telemetry Event model, an EventSource interface
// that abstracts where events come from (a live kernel probe on Linux, or a
// recorded fixture stream anywhere), a versioned detection rule set mapped to
// MITRE ATT&CK for Containers, plus forensic capture and response hooks.
//
// The design is deliberately split into a deterministic, portable core and a
// platform-specific edge. Every rule is a pure function of (Event, State) — it
// never reads the wall clock or a random source — so the same recorded stream
// always yields byte-identical detections. That makes the whole engine testable
// on any OS from committed fixtures, with the real eBPF attach parked behind
// Linux build tags (see NOTES.md). Phases 6 (reporting/MCP) and 7 (prevention)
// consume the Event and EventSource types and the generated SeccompProfile.
package runtime

// --- Event kinds ---------------------------------------------------------

// EventKind names the class of a telemetry event. A single Event carries
// exactly one of the typed sub-records (Process is always present because every
// event is attributed to an acting process; File/Network/Syscall are set to
// match Kind).
type EventKind string

const (
	// KindProcess is a process lifecycle event (exec/fork/exit). The Process
	// record describes the new/acting process and its ancestry.
	KindProcess EventKind = "process"
	// KindFile is a file access event (open/read/write/unlink/chmod). File is set.
	KindFile EventKind = "file"
	// KindNetwork is a socket event (connect/accept/dns). Network is set.
	KindNetwork EventKind = "network"
	// KindSyscall is a raw syscall of interest not covered by the above
	// (mount, setns, bpf, init_module, ptrace). Syscall is set. Kernel-level
	// abuse (LKM load, eBPF program load) is modeled here by syscall name,
	// exactly as an in-kernel probe would observe it.
	KindSyscall EventKind = "syscall"
)

// --- Event ---------------------------------------------------------------

// Event is one observation from the sensor. It is the atomic unit the detection
// engine consumes and the stable telemetry contract Phases 6 & 7 build on.
//
// Determinism: Seq gives a total order within a stream so replay is stable
// regardless of how a source batches or timestamps. TimeUnixNano is carried for
// forensics and correlation but is INJECTED (by the source), never read from the
// wall clock inside a rule — analysis must depend only on the data in the event.
type Event struct {
	// Seq is a monotonic sequence number within a single stream. It defines the
	// canonical processing order and makes replay deterministic.
	Seq uint64 `json:"seq"`
	// TimeUnixNano is the observation time in nanoseconds since the Unix epoch.
	// It is data, not a clock read: rules may compare event times to each other
	// but must never consult the host clock.
	TimeUnixNano int64 `json:"time_unix_nano,omitempty"`

	Kind EventKind `json:"kind"`

	// Container attributes the event to a workload. Full attribution is what
	// makes a node-level sensor useful: a syscall is noise until you know which
	// pod, image, and namespace it came from.
	Container ContainerInfo `json:"container"`
	// Process is the acting process and its ancestry chain. Always populated.
	Process ProcessInfo `json:"process"`

	File    *FileEvent    `json:"file,omitempty"`
	Network *NetworkEvent `json:"network,omitempty"`
	Syscall *SyscallEvent `json:"syscall,omitempty"`

	// Labels carry orchestrator/cloud enrichment (pod, namespace, node, cloud
	// account). Detection does not require them, but they travel into findings
	// and forensic bundles so an incident is actionable without a second lookup.
	Labels map[string]string `json:"labels,omitempty"`
}

// --- Attribution & process -----------------------------------------------

// ContainerInfo attributes an event to a container/workload. ImageID ties the
// running process back to the artifact the earlier phases scanned, which is what
// lets drift detection ask "did this binary ship in the image?".
type ContainerInfo struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	ImageID    string `json:"image_id,omitempty"`
	ImageRef   string `json:"image_ref,omitempty"`
	Runtime    string `json:"runtime,omitempty"` // docker, containerd, cri-o
	Privileged bool   `json:"privileged,omitempty"`
	// AIAgent marks a workload declared to be an AI/LLM agent (from an image
	// label or deploy annotation). The novel agent-runtime rules key off this;
	// it is inert unless those opt-in rules are enabled.
	AIAgent bool `json:"ai_agent,omitempty"`
}

// ProcessInfo describes the acting process and enough of its lineage to reason
// about behavior. Ancestry is the exe/comm chain from the container entrypoint
// down to this process — the single most useful signal for "a service just
// spawned a shell".
type ProcessInfo struct {
	PID  int    `json:"pid,omitempty"`
	PPID int    `json:"ppid,omitempty"`
	Comm string `json:"comm,omitempty"` // short process name (kernel comm)
	Exe  string `json:"exe,omitempty"`  // resolved executable path
	// Args is argv (excluding argv[0] duplication is not required; rules read it
	// tolerantly). Secret-shaped values are redacted before anything is logged.
	Args     []string `json:"args,omitempty"`
	UID      int      `json:"uid,omitempty"`
	GID      int      `json:"gid,omitempty"`
	CgroupID uint64   `json:"cgroup_id,omitempty"`
	// Ancestry is the ordered executable chain root→this (e.g.
	// ["/pause","/usr/sbin/nginx","/bin/sh"]). Sources that cannot resolve the
	// full chain may leave it empty; rules degrade gracefully.
	Ancestry []string `json:"ancestry,omitempty"`
	// Caps lists effective Linux capabilities held by the process (e.g.
	// "CAP_SYS_ADMIN"). Empty means unknown or none.
	Caps []string `json:"caps,omitempty"`
	// TTY reports whether the process is attached to a terminal — an
	// interactive shell in a container is far more suspicious than a scripted one.
	TTY bool `json:"tty,omitempty"`
	// StdioSocket is true when stdin/stdout is bound to a network socket, the
	// tell-tale of a reverse/bind shell.
	StdioSocket bool `json:"stdio_socket,omitempty"`
}

// --- Typed sub-records ---------------------------------------------------

// FileEvent describes a filesystem access. Op is a short verb (open, read,
// write, unlink, chmod, mount-target). Mode carries the resulting file mode when
// Op is chmod, so setuid-bit changes are visible.
type FileEvent struct {
	Path      string `json:"path"`
	Op        string `json:"op"`
	Flags     string `json:"flags,omitempty"` // e.g. "O_RDONLY", "O_WRONLY|O_CREAT"
	Mode      uint32 `json:"mode,omitempty"`  // octal file mode after the op
	TargetUID int    `json:"target_uid,omitempty"`
}

// NetworkEvent describes a socket operation. For connect events the remote
// address is what matters; DNS events carry the queried Domain.
type NetworkEvent struct {
	Op         string `json:"op"` // connect, accept, dns, listen
	Proto      string `json:"proto,omitempty"`
	LocalAddr  string `json:"local_addr,omitempty"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemotePort int    `json:"remote_port,omitempty"`
	Domain     string `json:"domain,omitempty"` // DNS name (query or SNI)
	// Direction is "egress" or "ingress"; egress to unknown endpoints is the C2 signal.
	Direction string `json:"direction,omitempty"`
}

// SyscallEvent describes a raw syscall of interest. Name is the syscall name
// ("mount", "setns", "bpf", "init_module"); Args carries the salient decoded
// arguments (e.g. bpf command, mount source/target) as strings for portability.
type SyscallEvent struct {
	Name   string            `json:"name"`
	Retval int               `json:"retval,omitempty"`
	Args   map[string]string `json:"args,omitempty"`
}

// --- Small helpers -------------------------------------------------------

// label returns a Labels value or "" — nil-safe for rule code.
func (e *Event) label(k string) string {
	if e.Labels == nil {
		return ""
	}
	return e.Labels[k]
}
