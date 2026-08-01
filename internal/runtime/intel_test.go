package runtime

import "testing"

func TestIOCFeedMatchNetwork(t *testing.T) {
	f := &IOCFeed{IPs: map[string]string{"203.0.113.5": "known-c2"}}
	if lbl, hit := f.MatchNetwork(&NetworkEvent{RemoteIP: "203.0.113.5"}); !hit || lbl != "known-c2" {
		t.Fatalf("want known-c2 hit, got %q hit=%v", lbl, hit)
	}
	if _, hit := f.MatchNetwork(&NetworkEvent{RemoteIP: "10.0.0.1"}); hit {
		t.Fatalf("false positive on internal IP")
	}
}

func TestLoadIOCFeedFromTestdata(t *testing.T) {
	f, err := LoadIOCFeed("testdata/intel-sample.json")
	if err != nil || f.IPs["203.0.113.5"] == "" {
		t.Fatalf("load failed: %v", err)
	}
}

func TestIntelRuleFiresOnlyWhenFeedSet(t *testing.T) {
	ev := Event{Kind: KindNetwork, Seq: 1, Network: &NetworkEvent{RemoteIP: "203.0.113.5", Direction: "egress"}}
	if fired(evalOne(t, Options{}, nil, ev), "DS-RAT-RT-014") {
		t.Fatalf("DS-RAT-RT-014 must be inert without a feed")
	}
	feed := &IOCFeed{IPs: map[string]string{"203.0.113.5": "known-c2"}}
	if !fired(evalOne(t, Options{IntelFeed: feed}, nil, ev), "DS-RAT-RT-014") {
		t.Fatalf("DS-RAT-RT-014 should fire with a feed")
	}
}
