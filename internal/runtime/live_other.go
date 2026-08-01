//go:build !linux

package runtime

// This file is the non-Linux fallback for the live event source. A kernel probe
// is inherently Linux/eBPF, so on every other platform (this build machine is
// darwin/arm64) NewLiveSource cleanly reports that live capture is unavailable
// and the caller should use replay mode. The identical signature to the Linux
// build means cmd/ and tests compile and behave the same everywhere; only the
// error differs. This is how the whole tree stays green on darwin while the
// kernel-specific work lives behind //go:build linux.

// NewLiveSource reports that live kernel capture is unavailable off Linux.
// Callers fall back to a ReplaySource built from a recorded scenario.
func NewLiveSource(cfg LiveConfig) (EventSource, error) {
	_ = cfg
	return nil, ErrLiveUnsupported
}
