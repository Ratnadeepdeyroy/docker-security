//go:build !linux

package runtime

// This file is the non-Linux fallback for the /proc-polling live EventSource.
// Polling /proc is inherently Linux-specific, so on every other platform (this
// build machine is darwin/arm64) NewProcSource cleanly reports that live
// capture is unavailable, matching NewLiveSource's behavior in live_other.go.

// NewProcSource reports that live /proc-based capture is unavailable off
// Linux. Callers fall back to a ReplaySource built from a recorded scenario.
func NewProcSource(cfg LiveConfig, resolver *ContainerResolver) (*ProcSource, error) {
	_ = cfg
	_ = resolver
	return nil, ErrLiveUnsupported
}
