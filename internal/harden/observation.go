package harden

// --- The behavioural input contract (decoupled from Phase 5) -----------------
//
// Profile generation needs to know what a workload actually *does*: which
// syscalls it issues, which capabilities it exercises, which files it touches,
// whether it talks to the network. On a live system Phase 5 (runtime telemetry)
// produces that from eBPF/ptrace tracing. Phase 5 is being built in parallel and
// may not exist yet, so we do NOT import internal/runtime. Instead we define this
// small local input type. A Phase-5 adapter is a trivial mapping into it, and
// the static path (a recorded/declared Observation loaded from JSON) works today.
//
// Master action (NOTES.md): wire an internal/runtime → harden.Observation adapter
// once the telemetry schema lands, keeping this type as the stable boundary.

// Observation is a recorded or declared summary of a workload's runtime
// behaviour. It is intentionally minimal — just enough for least-privilege
// profile generation — and JSON-serialisable so it can be committed as a fixture
// or streamed from a telemetry collector.
type Observation struct {
	// Workload is a human label used to name the generated profiles.
	Workload string `json:"workload,omitempty"`

	// Syscalls are the syscall names the workload was seen to issue (e.g.
	// "openat", "connect"). Order is irrelevant; duplicates are ignored.
	Syscalls []string `json:"syscalls,omitempty"`

	// Capabilities are the Linux capabilities the workload exercised, in any
	// spelling (normalised on use).
	Capabilities []string `json:"capabilities,omitempty"`

	// FileReads / FileWrites / FileExecs are filesystem paths the workload
	// accessed in each mode. Globs are allowed and passed through to AppArmor
	// verbatim (e.g. "/var/log/**").
	FileReads  []string `json:"file_reads,omitempty"`
	FileWrites []string `json:"file_writes,omitempty"`
	FileExecs  []string `json:"file_execs,omitempty"`

	// Network is true if the workload used the network at all. A false value
	// lets the AppArmor generator omit the (broad) network rule entirely.
	Network bool `json:"network,omitempty"`

	// Complete indicates the trace is believed to cover the workload's full
	// behaviour (steady state reached). The profile-from-behaviour loop uses this
	// to decide whether it is safe to tighten to enforce mode; an incomplete
	// trace should stay in audit/log mode. See bundle.go.
	Complete bool `json:"complete,omitempty"`
}

// syscallSet returns the observed syscalls as a normalised, deduplicated set.
func (o Observation) syscallSet() []string { return dedupeSort(o.Syscalls) }

// capSet returns the observed capabilities in canonical bare upper-case form.
func (o Observation) capSet() []string { return normalizeCaps(o.Capabilities) }
