package netmon

import (
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// TestEgressIntentClassification checks the intent model buckets a steady named
// destination as intended and a raw-IP/odd-port one-off as anomalous, each with
// a rationale (the property that lets an agent approve an allowlist).
func TestEgressIntentClassification(t *testing.T) {
	c := loadFixture(t, "capture_baseline.json")
	logs := BuildFlowLogs(c)
	if len(logs) != 1 {
		t.Fatalf("baseline should have one workload, got %d", len(logs))
	}
	intents := ClassifyEgress(logs[0], Options{})

	byDest := map[string]EgressIntent{}
	for _, in := range intents {
		byDest[in.Dest] = in
	}

	stripe, ok := byDest["api.stripe.com"]
	if !ok || stripe.Class != ClassIntended {
		t.Errorf("api.stripe.com should be intended, got %+v", stripe)
	}
	if len(stripe.Reasons) == 0 {
		t.Error("intended classification must carry a rationale")
	}
	tor, ok := byDest["185.220.101.5"]
	if !ok || tor.Class != ClassAnomalous {
		t.Errorf("raw-IP one-off should be anomalous, got %+v", tor)
	}
	// The internal DB is not external egress and must not be classified.
	if _, ok := byDest["db.shop.svc"]; ok {
		t.Error("internal peer should not appear in egress intent classification")
	}
}

// TestIntentDetectorOffByDefault confirms the anomalous-egress finding only
// appears when intent modelling is explicitly enabled.
func TestIntentDetectorOffByDefault(t *testing.T) {
	c := loadFixture(t, "capture_baseline.json")
	off := kinds(Analyze(c, Options{}).Anomalies)
	if len(off[KindAnomalousEg]) != 0 {
		t.Error("anomalous-egress must not fire with default options")
	}
	on := kinds(Analyze(c, Options{EnableIntent: true}).Anomalies)
	if len(on[KindAnomalousEg]) == 0 {
		t.Error("anomalous-egress should fire when intent modelling is enabled")
	}
}

// TestAgentEgressGovernance is the novel AI-age feature: an agent workload
// reaching an unknown LLM-looking host is HIGH; an unknown non-model host is
// MEDIUM; a known model endpoint is not flagged. Off unless enabled.
func TestAgentEgressGovernance(t *testing.T) {
	c := loadFixture(t, "capture_agent.json")

	// Off by default.
	if len(kinds(Analyze(c, Options{}).Anomalies)[KindAgentEgress]) != 0 {
		t.Fatal("agent-egress governance must be off by default")
	}

	as := kinds(Analyze(c, Options{EnableAgentEgress: true}).Anomalies)[KindAgentEgress]
	byDest := map[string]Anomaly{}
	for _, a := range as {
		byDest[a.Dest] = a
	}
	if _, ok := byDest["api.openai.com"]; ok {
		t.Error("known model host api.openai.com should not be flagged")
	}
	llm, ok := byDest["llm-proxy.shadow.example"]
	if !ok || llm.Severity != engine.SeverityHigh {
		t.Errorf("unknown LLM-looking host should be HIGH, got %+v", llm)
	}
	tele, ok := byDest["telemetry.thirdparty.example"]
	if !ok || tele.Severity != engine.SeverityMedium {
		t.Errorf("unknown non-model host should be MEDIUM, got %+v", tele)
	}
}

// TestAgentEgressIgnoresNonAgents ensures governance only scrutinises agent
// workloads, so ordinary services are not spammed with model-egress findings.
func TestAgentEgressIgnoresNonAgents(t *testing.T) {
	c := loadFixture(t, "capture_baseline.json") // checkout is not an agent
	if len(kinds(Analyze(c, Options{EnableAgentEgress: true}).Anomalies)[KindAgentEgress]) != 0 {
		t.Error("agent-egress governance must not fire on non-agent workloads")
	}
}
