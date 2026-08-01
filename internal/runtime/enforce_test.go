package runtime

import "testing"

// TestEnforcingResponderRespectsGate is the key correctness proof: destructive
// side effects (kill/pause) must fire only when the policy is armed (enforce
// mode + acknowledged). In detect mode, intent is still recorded but nothing
// destructive happens.
func TestEnforcingResponderRespectsGate(t *testing.T) {
	mk := func(p ResponsePolicy, killed, paused *int) *EnforcingResponder {
		return &EnforcingResponder{
			Policy:   p,
			Recorder: &RecordingResponder{},
			kill:     func(int) error { *killed++; return nil },
			pause:    func(string) error { *paused++; return nil },
			isolate:  func(string) error { return nil },
		}
	}

	var k, p int
	detect := mk(DefaultResponsePolicy(), &k, &p)
	_ = detect.Do(Action{Kind: ActionKill, PID: 42})
	_ = detect.Do(Action{Kind: ActionQuarantine, Container: "c1"})
	if k != 0 || p != 0 {
		t.Fatalf("side effects fired in detect mode: kill=%d pause=%d", k, p)
	}
	if len(detect.Recorder.Actions) != 2 {
		t.Fatalf("detect must still record intent, got %d", len(detect.Recorder.Actions))
	}

	var k2, p2 int
	armed := mk(ResponsePolicy{Mode: ResponseEnforce, Acknowledged: true, KillSeverity: 0}, &k2, &p2)
	_ = armed.Do(Action{Kind: ActionKill, PID: 42})
	_ = armed.Do(Action{Kind: ActionQuarantine, Container: "c1"})
	if k2 != 1 || p2 != 1 {
		t.Fatalf("armed enforce did not act: kill=%d pause=%d", k2, p2)
	}
	if len(armed.Recorder.Actions) != 2 {
		t.Fatalf("armed must also record intent, got %d", len(armed.Recorder.Actions))
	}
}

// TestEnforcingResponderNotArmedUnacknowledged proves the double-gate: enforce
// mode alone (without acknowledgement) must not be enough to arm destructive
// action.
func TestEnforcingResponderNotArmedUnacknowledged(t *testing.T) {
	var k, p int
	r := &EnforcingResponder{
		Policy:   ResponsePolicy{Mode: ResponseEnforce, Acknowledged: false},
		Recorder: &RecordingResponder{},
		kill:     func(int) error { k++; return nil },
		pause:    func(string) error { p++; return nil },
		isolate:  func(string) error { return nil },
	}
	_ = r.Do(Action{Kind: ActionKill, PID: 1})
	if k != 0 {
		t.Fatalf("unacknowledged enforce must not kill, got k=%d", k)
	}
	if len(r.Recorder.Actions) != 1 {
		t.Fatalf("want 1 recorded action")
	}
}

// TestEnforcingResponderAlertNeverActs proves alert actions never trigger a
// side effect, even when armed.
func TestEnforcingResponderAlertNeverActs(t *testing.T) {
	var k, p int
	r := &EnforcingResponder{
		Policy:   ResponsePolicy{Mode: ResponseEnforce, Acknowledged: true},
		Recorder: &RecordingResponder{},
		kill:     func(int) error { k++; return nil },
		pause:    func(string) error { p++; return nil },
		isolate:  func(string) error { return nil },
	}
	if err := r.Do(Action{Kind: ActionAlert}); err != nil {
		t.Fatalf("alert Do should be nil: %v", err)
	}
	if k != 0 || p != 0 {
		t.Fatalf("alert must never act: kill=%d pause=%d", k, p)
	}
	if len(r.Recorder.Actions) != 1 {
		t.Fatalf("want 1 recorded action")
	}
}

// TestNewEnforcingResponderInertWhenDetect proves the platform constructor is
// safe by default: in detect mode, Do never invokes the platform side effects
// regardless of platform, and alert actions always succeed.
func TestNewEnforcingResponderInertWhenDetect(t *testing.T) {
	r := NewEnforcingResponder(DefaultResponsePolicy())
	if err := r.Do(Action{Kind: ActionAlert}); err != nil {
		t.Fatalf("alert Do should be nil: %v", err)
	}
	if len(r.Recorder.Actions) != 1 {
		t.Fatalf("want 1 recorded action")
	}
	// Detect mode must never call the destructive kill/pause paths.
	if err := r.Do(Action{Kind: ActionKill, PID: 99999}); err != nil {
		t.Fatalf("detect-mode kill Do should be nil, got %v", err)
	}
}
