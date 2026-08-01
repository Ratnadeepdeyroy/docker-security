//go:build !linux

package runtime

// NewEnforcingResponder builds the platform responder. Off-Linux, the
// destructive side effects are inert (ErrLiveUnsupported): even if a caller
// somehow arms enforce mode on this platform, there is no live kernel/runtime
// integration to act against, so Do returns an error instead of silently
// doing nothing or doing something unsupported.
func NewEnforcingResponder(p ResponsePolicy) *EnforcingResponder {
	inert := func(int) error { return ErrLiveUnsupported }
	inertC := func(string) error { return ErrLiveUnsupported }
	return &EnforcingResponder{
		Policy:   p,
		Recorder: &RecordingResponder{},
		kill:     inert,
		pause:    inertC,
		isolate:  inertC,
	}
}
