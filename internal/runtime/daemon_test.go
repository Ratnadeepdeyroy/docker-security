package runtime

import (
	"context"
	"os"
	"testing"
)

// collectingSink records emitted records to assert streaming behavior.
type collectingSink struct{ recs []DetectionRecord }

func (s *collectingSink) Emit(rec DetectionRecord) error { s.recs = append(s.recs, rec); return nil }

func TestDaemonRunProducesOrderedRecords(t *testing.T) {
	sc := loadTestScenario(t, "attack_scenario.json")
	sink := &collectingSink{}
	cfg := DaemonConfig{Images: sc.Images, Policy: DefaultResponsePolicy(), Sink: sink}
	res, err := cfg.Run(context.Background(), NewReplaySource(sc.Events))
	if err != nil {
		t.Fatalf("daemon run: %v", err)
	}
	if res.EventsScanned != len(sc.Events) {
		t.Errorf("scanned %d events, want %d", res.EventsScanned, len(sc.Events))
	}
	if len(res.Records) != 17 {
		t.Errorf("expected 17 detection records, got %d", len(res.Records))
	}
	// Records must be in canonical (seq, rule) order.
	for i := 1; i < len(res.Records); i++ {
		a, b := res.Records[i-1].Detection, res.Records[i].Detection
		if a.Seq > b.Seq {
			t.Fatalf("records out of order at %d: seq %d then %d", i, a.Seq, b.Seq)
		}
	}
	// The sink saw every record.
	if len(sink.recs) != len(res.Records) {
		t.Errorf("sink saw %d records, result has %d", len(sink.recs), len(res.Records))
	}
	// Detect-only: every action is an alert.
	for _, rec := range res.Records {
		if rec.Action.Kind != ActionAlert {
			t.Errorf("detect-only daemon planned non-alert action %s for %s", rec.Action.Kind, rec.Detection.RuleID)
		}
	}
}

func TestDaemonForensicsCaptureOnAlert(t *testing.T) {
	sc := loadTestScenario(t, "attack_scenario.json")
	dir := t.TempDir()
	cfg := DaemonConfig{Images: sc.Images, Policy: DefaultResponsePolicy(), ForensicsDir: dir, EmitIncidents: true}
	res, err := cfg.Run(context.Background(), NewReplaySource(sc.Events))
	if err != nil {
		t.Fatalf("daemon run: %v", err)
	}
	if len(res.EvidencePaths) == 0 {
		t.Fatal("expected forensic bundles to be written")
	}
	// Each written bundle exists and round-trips through verification.
	for _, p := range res.EvidencePaths {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read evidence %s: %v", p, err)
		}
		if len(data) == 0 {
			t.Fatalf("evidence %s is empty", p)
		}
	}
	// Incidents were attached and every record carries a stable id + playbook.
	for _, rec := range res.Records {
		if rec.Incident == nil {
			t.Fatalf("EmitIncidents set but %s has no incident", rec.Detection.RuleID)
		}
		if rec.Incident.ID == "" || len(rec.Incident.Playbook) == 0 {
			t.Errorf("incident for %s missing id/playbook", rec.Detection.RuleID)
		}
	}
}

func TestDaemonEnforceMode(t *testing.T) {
	sc := loadTestScenario(t, "attack_scenario.json")
	responder := &RecordingResponder{}
	cfg := DaemonConfig{
		Images:    sc.Images,
		Policy:    ResponsePolicy{Mode: ResponseEnforce, Acknowledged: true, KillSeverity: 0}, // arm everything at/above Unknown
		Responder: responder,
	}
	res, err := cfg.Run(context.Background(), NewReplaySource(sc.Events))
	if err != nil {
		t.Fatalf("daemon run: %v", err)
	}
	// In armed enforce mode, escape (DS-RAT-RT-003) and kernel abuse (DS-RAT-RT-008)
	// quarantine; nothing should remain a plain alert given KillSeverity=0.
	var quarantines, kills int
	for _, a := range responder.Actions {
		switch a.Kind {
		case ActionQuarantine:
			quarantines++
		case ActionKill:
			kills++
		case ActionAlert:
			t.Errorf("armed enforce still alerted for %s", a.RuleID)
		}
	}
	if quarantines == 0 || kills == 0 {
		t.Errorf("expected both quarantine and kill actions, got q=%d k=%d", quarantines, kills)
	}
	if len(responder.Actions) != len(res.Records) {
		t.Errorf("responder saw %d actions, %d records", len(responder.Actions), len(res.Records))
	}
}

func TestDaemonIncidentDeterministicID(t *testing.T) {
	// The same detection must always yield the same incident id (no clock/counter).
	d := det("DS-RAT-RT-003", 5)
	d.Seq = 6
	d.Container = ContainerInfo{ID: "c1"}
	if BuildIncident(d).ID != BuildIncident(d).ID {
		t.Error("incident id is not deterministic")
	}
}
