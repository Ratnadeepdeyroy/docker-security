package runtime

// EnforcingResponder is a real, side-effecting Responder: it kills processes
// and quarantines containers when the policy is armed. The side effects are
// injected function fields, wired per platform by NewEnforcingResponder
// (enforce_linux.go / enforce_other.go) — so the gating logic in Do is shared,
// identical, and safe by default regardless of platform, while only the actual
// OS integration differs between builds.
type EnforcingResponder struct {
	Policy   ResponsePolicy
	Recorder *RecordingResponder

	// Side effects are injected function fields so Do is fully unit-testable
	// without touching the OS, and so platform wiring lives only in the
	// per-platform constructor.
	kill    func(pid int) error
	pause   func(container string) error
	isolate func(container string) error
}

// Do always records the action (so alert/audit trails are unaffected by
// enforcement posture); it performs a destructive side effect ONLY when the
// policy is armed (enforce mode + acknowledged). Alert actions never act.
func (r *EnforcingResponder) Do(a Action) error {
	_ = r.Recorder.Do(a)
	if !r.Policy.armed() {
		return nil
	}
	switch a.Kind {
	case ActionKill:
		return r.kill(a.PID)
	case ActionQuarantine:
		if err := r.pause(a.Container); err != nil {
			return err
		}
		return r.isolate(a.Container)
	default:
		return nil
	}
}
