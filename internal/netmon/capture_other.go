//go:build !linux

package netmon

import (
	"context"
	"errors"
	"runtime"
)

// ErrLiveCaptureUnavailable is returned by the live Source on non-Linux
// platforms. eBPF flow capture is Linux-only; everywhere else the deterministic
// offline path (a RecordedSource over a fixture) is the supported mode. This
// mirrors the Linux sentinel so callers handle both builds identically.
var ErrLiveCaptureUnavailable = errors.New("netmon: live capture unsupported on this platform (build is not linux) — use a recorded capture")

// LiveSource is the non-Linux stub. It implements Source so the whole package
// (and its tests) build and run on darwin/arm64, but every Capture reports the
// platform limitation rather than pretending to observe traffic.
type LiveSource struct {
	Iface string
}

// NewLiveSource returns a live capture source. On non-Linux builds it only ever
// reports ErrLiveCaptureUnavailable.
func NewLiveSource(iface string) *LiveSource { return &LiveSource{Iface: iface} }

// Capture always fails on non-Linux platforms, naming the current GOOS so the
// message is actionable.
func (s *LiveSource) Capture(_ context.Context) (*Capture, error) {
	return nil, errors.New(ErrLiveCaptureUnavailable.Error() + " (GOOS=" + runtime.GOOS + ")")
}
