package runtime

import (
	"context"
	"errors"
)

// --- Event source contract -----------------------------------------------

// EventSource is where the detector gets its telemetry. It abstracts over a
// live kernel probe (Linux/eBPF, built behind a tag) and an offline recorded
// stream (the portable, deterministic path used everywhere including CI). Phases
// 6 and 7 consume this interface to tap the same event feed without caring how
// events are produced.
//
// A source is single-consumer: Next is called from one goroutine. Bounded
// sources (replay) return io.EOF once drained; unbounded sources (live) block
// until an event arrives or ctx is cancelled.
type EventSource interface {
	// Next returns the next event in order. It returns io.EOF when a bounded
	// source is exhausted, and respects ctx for cancellation on live sources.
	Next(ctx context.Context) (Event, error)
	// Close releases resources (open files, kernel maps, ring buffers). It is
	// safe to call Close more than once.
	Close() error
}

// ErrLiveUnsupported is returned by NewLiveSource on platforms without a kernel
// probe (everything that is not Linux). Callers should fall back to replay.
var ErrLiveUnsupported = errors.New("runtime: live kernel event source is only available on Linux")

// ShellKillEnforcer is implemented by an EventSource that can enforce in-kernel:
// arming it makes the source SIGKILL a shell execing inside a container before it
// runs. Only the eBPF source implements it; the daemon arms it only in
// acknowledged enforce mode.
type ShellKillEnforcer interface {
	ArmShellKill() error
}

// ErrLiveKernelParked is returned by the Linux NewLiveSource until the eBPF
// loader is wired in (a deliberately parked master action — see NOTES.md). It
// lets the daemon compile and run on Linux today, failing loudly and safely
// rather than pretending to attach to the kernel.
var ErrLiveKernelParked = errors.New("runtime: live eBPF attach is not built into this binary yet (see NOTES.md master action); use replay mode")

// LiveConfig configures a live kernel source. It is intentionally small now; the
// eBPF loader will grow it (probe selection, ring-buffer sizing, CO-RE BTF path)
// when that dependency lands.
type LiveConfig struct {
	// RingBufferBytes is the requested per-CPU ring-buffer size for the future
	// eBPF loader. Zero selects a sane default when the loader is implemented.
	RingBufferBytes int
	// Probes optionally restricts which probe groups to attach (process, file,
	// network, syscall). Empty means all.
	Probes []string
}
