package compliance

import (
	"testing"
	"time"
)

func waivedReport() *Report {
	return sampleBenchmark().Run(fixedAssessor(map[string]Status{
		"2.1": StatusPass, "2.2": StatusFail, "2.10": StatusFail,
	}))
}

func TestWaiverDemotesButPreservesRawStatus(t *testing.T) {
	rep := waivedReport()
	now := time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)
	ws := NewWaivers([]Waiver{
		{Control: "2.2", Benchmark: "docker", Reason: "compensating control in place", Owner: "sec", Expires: "2026-12-31T00:00:00Z"},
	})
	ws.Apply(rep, "docker", now)

	var r22 Result
	for _, r := range rep.Results {
		if r.Control.ID == "2.2" {
			r22 = r
		}
	}
	if !r22.Waived {
		t.Fatalf("2.2 should be waived")
	}
	if r22.Status != StatusFail {
		t.Errorf("raw status should still be FAIL for the audit trail, got %s", r22.Status)
	}
	if r22.effectiveStatus() != StatusInfo {
		t.Errorf("effective status of a waived FAIL should be INFO, got %s", r22.effectiveStatus())
	}
	// The remaining un-waived FAIL (2.10) still trips the gate; had both been
	// waived the gate would pass.
	if !rep.FailsAt(false) {
		t.Errorf("un-waived FAIL 2.10 should still fail the gate")
	}
}

func TestExpiredWaiverIsIgnored(t *testing.T) {
	rep := waivedReport()
	now := time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)
	ws := NewWaivers([]Waiver{
		{Control: "2.2", Reason: "temporary", Expires: "2026-01-01T00:00:00Z"}, // already past
	})
	ws.Apply(rep, "docker", now)
	for _, r := range rep.Results {
		if r.Control.ID == "2.2" && r.Waived {
			t.Errorf("expired waiver must not apply")
		}
	}
}

func TestWaiverWithoutExpiryIsNotHonored(t *testing.T) {
	rep := waivedReport()
	ws := NewWaivers([]Waiver{{Control: "2.2", Reason: "forever"}}) // no expiry
	ws.Apply(rep, "docker", time.Now())
	for _, r := range rep.Results {
		if r.Control.ID == "2.2" && r.Waived {
			t.Errorf("a waiver with no expiry must not be honored")
		}
	}
}

func TestWaiverBenchmarkScoping(t *testing.T) {
	rep := waivedReport()
	now := time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)
	// Waiver scoped to k8s must not touch a docker report.
	ws := NewWaivers([]Waiver{{Control: "2.2", Benchmark: "k8s", Reason: "x", Expires: "2027-01-01T00:00:00Z"}})
	ws.Apply(rep, "docker", now)
	for _, r := range rep.Results {
		if r.Control.ID == "2.2" && r.Waived {
			t.Errorf("k8s-scoped waiver must not apply to a docker report")
		}
	}
}

func TestExpiringLists(t *testing.T) {
	now := time.Date(2026, 7, 4, 0, 0, 0, 0, time.UTC)
	ws := NewWaivers([]Waiver{
		{Control: "2.2", Reason: "soon", Expires: "2026-07-20T00:00:00Z"},  // within 30d
		{Control: "2.1", Reason: "later", Expires: "2027-01-01T00:00:00Z"}, // outside 30d
		{Control: "2.3", Reason: "past", Expires: "2026-01-01T00:00:00Z"},  // already expired
	})
	exp := ws.Expiring(30*24*time.Hour, now)
	if len(exp) != 1 || exp[0].Control != "2.2" {
		t.Errorf("expected only 2.2 expiring within 30d, got %+v", exp)
	}
}

func TestBareDateExpiryParses(t *testing.T) {
	w := Waiver{Control: "2.2", Reason: "x", Expires: "2026-12-31"}
	if w.expiryTime().IsZero() {
		t.Errorf("bare YYYY-MM-DD expiry should parse")
	}
}
