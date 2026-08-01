package netmon

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// loadFixture reads a testdata capture, failing the test on any error.
func loadFixture(t *testing.T, name string) *Capture {
	t.Helper()
	c, err := LoadCapture(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("LoadCapture(%s): %v", name, err)
	}
	return c
}

func TestAddressClassification(t *testing.T) {
	cases := []struct {
		ip                       string
		internal, external, imds bool
	}{
		{"10.9.0.20", true, false, false},
		{"192.168.1.1", true, false, false},
		{"172.16.5.5", true, false, false},
		{"34.200.0.10", false, true, false},
		{"169.254.169.254", true, false, true}, // link-local range is internal, but IMDS-classified
		{"169.254.169.253", true, false, true},
		{"", false, false, false},
		{"not-an-ip", false, false, false},
	}
	for _, c := range cases {
		if got := IsInternal(c.ip); got != c.internal {
			t.Errorf("IsInternal(%q)=%v want %v", c.ip, got, c.internal)
		}
		if got := IsExternal(c.ip); got != c.external {
			t.Errorf("IsExternal(%q)=%v want %v", c.ip, got, c.external)
		}
		if got := IsIMDS(c.ip); got != c.imds {
			t.Errorf("IsIMDS(%q)=%v want %v", c.ip, got, c.imds)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	// A single repeated char carries no information.
	if h := shannonEntropy("aaaaaaaa"); h != 0 {
		t.Errorf("entropy of constant string = %v, want 0", h)
	}
	// A high-variety string should exceed the DGA threshold default.
	if h := shannonEntropy("q7z2x9k4vw1m8n3p"); h < 3.6 {
		t.Errorf("entropy of random-looking string = %v, want >= 3.6", h)
	}
	// More variety => higher entropy.
	if shannonEntropy("abcd") <= shannonEntropy("aabb") {
		t.Error("expected more distinct characters to raise entropy")
	}
}

func TestParentAndSubLabels(t *testing.T) {
	if got := parentDomain("abc.def.tunnel.example"); got != "tunnel.example" {
		t.Errorf("parentDomain = %q, want tunnel.example", got)
	}
	if got := subLabels("abc.def.tunnel.example", "tunnel.example"); got != "abc.def" {
		t.Errorf("subLabels = %q, want abc.def", got)
	}
	if got := parentDomain("example.com"); got != "example.com" {
		t.Errorf("parentDomain of 2-label = %q, want example.com", got)
	}
}

func TestBuildFlowLogsAttributesAndAggregates(t *testing.T) {
	c := loadFixture(t, "capture_threats.json")
	logs := BuildFlowLogs(c)

	// Every workload in the capture must appear exactly once, in id order.
	if len(logs) != len(c.Workloads) {
		t.Fatalf("got %d flow logs, want %d workloads", len(logs), len(c.Workloads))
	}
	for i := 1; i < len(logs); i++ {
		if logs[i-1].Workload.ID > logs[i].Workload.ID {
			t.Errorf("flow logs not sorted by workload id: %q before %q", logs[i-1].Workload.ID, logs[i].Workload.ID)
		}
	}

	// The malware workload's IMDS destination must be aggregated and flagged.
	var malware *FlowLog
	for _, fl := range logs {
		if fl.Workload.ID == "prod/malware" {
			malware = fl
		}
	}
	if malware == nil {
		t.Fatal("prod/malware flow log missing")
	}
	var sawIMDS bool
	for _, d := range malware.Dests {
		if d.IMDS {
			sawIMDS = true
			if d.Count != 3 {
				t.Errorf("IMDS dest count = %d, want 3 (aggregated)", d.Count)
			}
		}
	}
	if !sawIMDS {
		t.Error("expected an IMDS destination in the malware flow log")
	}
}

func TestDecodeCaptureRejectsGarbageAndTrailingData(t *testing.T) {
	if _, err := DecodeCapture(strings.NewReader("this is not json")); err == nil {
		t.Error("garbage input should error, not parse")
	}
	if _, err := DecodeCapture(strings.NewReader(`{"workloads":[],"flows":[]}{"extra":1}`)); err == nil {
		t.Error("trailing data should be rejected")
	}
	if _, err := DecodeCapture(strings.NewReader(`{"workloads":[],"flows":[],"bogus_field":true}`)); err == nil {
		t.Error("unknown fields should be rejected (schema drift guard)")
	}
}

func TestRecordedSourceRoundTrips(t *testing.T) {
	c := loadFixture(t, "capture_baseline.json")
	src := NewRecordedSource(c)
	got, err := src.Capture(context.Background())
	if err != nil {
		t.Fatalf("recorded source: %v", err)
	}
	if got != c {
		t.Error("recorded source should return the stored capture")
	}
	// The nil-capture case must error rather than panic.
	if _, err := (&RecordedSource{}).Capture(context.Background()); err == nil {
		t.Error("empty recorded source should error")
	}
}

// TestLiveSourceUnavailable proves the cross-platform stub: on the darwin build
// machine live capture is unsupported and must report that cleanly (never
// panic, never pretend to observe traffic).
func TestLiveSourceUnavailable(t *testing.T) {
	_, err := NewLiveSource("eth0").Capture(context.Background())
	if err == nil {
		t.Fatal("live capture must be unavailable in the offline/darwin build")
	}
	if !strings.Contains(err.Error(), "netmon: live capture") {
		t.Errorf("unexpected live-capture error: %v", err)
	}
}
