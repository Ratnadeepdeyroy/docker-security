//go:build linux

package netmon

import (
	"context"
	"errors"
)

// ErrLiveCaptureUnavailable is returned by the live Source until real capture is
// wired. It is a sentinel so callers can distinguish "no capture backend" from a
// genuine runtime failure and fall back to a recorded Source.
var ErrLiveCaptureUnavailable = errors.New("netmon: live capture not wired (eBPF backend parked — see NOTES.md)")

// LiveSource is the placeholder for the Linux eBPF flow/DNS probe. On Linux the
// real implementation will attach kprobes/tracepoints (or consume Phase-5
// telemetry) and stream Flow/DNSEvent records. Loading an eBPF program requires
// a loader dependency and CAP_BPF, which are out of scope for the deterministic
// offline core, so this returns the sentinel today. The interface is identical
// to the non-Linux stub so the rest of the package is platform-agnostic.
type LiveSource struct {
	// Iface optionally names the interface to attach to; unused until wired.
	Iface string
}

// NewLiveSource returns a live capture source for the given interface.
func NewLiveSource(iface string) *LiveSource { return &LiveSource{Iface: iface} }

// Capture reports that live capture is not yet available on this build. Real
// eBPF attach + ringbuffer consumption is parked as a master action; callers
// should use a RecordedSource for offline analysis.
func (s *LiveSource) Capture(_ context.Context) (*Capture, error) {
	return nil, ErrLiveCaptureUnavailable
}
