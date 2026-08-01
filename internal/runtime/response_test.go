package runtime

import (
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

func det(ruleID string, sev engine.Severity) Detection {
	return Detection{RuleID: ruleID, Severity: sev, Container: ContainerInfo{ID: "c1"}, Process: ProcessInfo{PID: 42}}
}

func TestDefaultPolicyIsAlertOnly(t *testing.T) {
	p := DefaultResponsePolicy()
	for _, d := range []Detection{
		det("DS-RAT-RT-003", engine.SeverityCritical),
		det("DS-RAT-RT-008", engine.SeverityCritical),
		det("DS-RAT-RT-001", engine.SeverityHigh),
	} {
		if a := p.Plan(d); a.Kind != ActionAlert {
			t.Errorf("detect mode must alert only; %s got %s", d.RuleID, a.Kind)
		}
	}
}

func TestEnforceRequiresAcknowledgement(t *testing.T) {
	// Enforce mode WITHOUT the acknowledgement must degrade to alert — you can
	// never accidentally arm destructive response.
	p := ResponsePolicy{Mode: ResponseEnforce, Acknowledged: false, KillSeverity: engine.SeverityHigh}
	if a := p.Plan(det("DS-RAT-RT-003", engine.SeverityCritical)); a.Kind != ActionAlert {
		t.Errorf("unacknowledged enforce must alert only, got %s", a.Kind)
	}
}

func TestArmedEnforceContainsSevereDetections(t *testing.T) {
	p := ResponsePolicy{Mode: ResponseEnforce, Acknowledged: true, KillSeverity: engine.SeverityHigh}

	// Escape and kernel abuse quarantine the whole workload.
	if a := p.Plan(det("DS-RAT-RT-003", engine.SeverityCritical)); a.Kind != ActionQuarantine {
		t.Errorf("escape should quarantine, got %s", a.Kind)
	}
	if a := p.Plan(det("DS-RAT-RT-008", engine.SeverityCritical)); a.Kind != ActionQuarantine {
		t.Errorf("kernel abuse should quarantine, got %s", a.Kind)
	}
	// Other severe detections kill the offending process.
	if a := p.Plan(det("DS-RAT-RT-006", engine.SeverityHigh)); a.Kind != ActionKill {
		t.Errorf("severe process detection should kill, got %s", a.Kind)
	}
	// Below the kill threshold → alert even when armed.
	if a := p.Plan(det("DS-RAT-RT-004", engine.SeverityMedium)); a.Kind != ActionAlert {
		t.Errorf("sub-threshold detection should alert, got %s", a.Kind)
	}
}

func TestRecordingResponderCapturesActions(t *testing.T) {
	r := &RecordingResponder{}
	_ = r.Do(Action{Kind: ActionAlert, RuleID: "DS-RAT-RT-001"})
	_ = r.Do(Action{Kind: ActionKill, RuleID: "DS-RAT-RT-006"})
	if len(r.Actions) != 2 {
		t.Fatalf("expected 2 recorded actions, got %d", len(r.Actions))
	}
	if r.Actions[1].Kind != ActionKill {
		t.Errorf("recorded action mismatch: %+v", r.Actions[1])
	}
}
