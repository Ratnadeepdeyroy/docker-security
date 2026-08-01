package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/store"
)

// ExampleServer shows an AI agent driving the platform over MCP: it lists tools,
// runs a blast-radius inventory query, gets a machine-readable explanation, and
// asks for a prioritized remediation plan — all deterministic, no model present.
func ExampleServer() {
	// A store seeded with one scanned image carrying a vulnerable component.
	st := store.NewMemory()
	st.Put(&store.Scan{
		Image:      "acme/api:1.2.3",
		RecordedAt: fixedClock(),
		Labels:     map[string]string{"owner": "team-platform"},
		Report: &engine.Report{Target: "acme/api:1.2.3", Findings: []engine.Finding{
			{RuleID: "DS-RAT-VULN-042", Module: "vuln", Severity: engine.SeverityCritical, Title: "openssl CVE-2022-3602",
				Remediation: "Upgrade openssl to 3.0.7"},
		}},
		Components: []store.Component{{Name: "openssl", Version: "3.0.1"}},
	})

	reg := engine.NewRegistry()
	reg.Register(fakeModule{})
	srv := New(reg, WithStore(st), WithClock(fixedClock))

	send := func(method string, params any) *response {
		p, _ := json.Marshal(params)
		req, _ := json.Marshal(request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: method, Params: p})
		out, _ := srv.handleMessage(context.Background(), req)
		var r response
		json.Unmarshal(out, &r)
		return &r
	}
	toolText := func(r *response) map[string]any {
		txt := r.Result.(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
		var m map[string]any
		json.Unmarshal([]byte(txt), &m)
		return m
	}

	// 1. Discover tools.
	tools := send("tools/list", nil).Result.(map[string]any)["tools"].([]any)
	fmt.Printf("tools available: %d\n", len(tools))

	// 2. Blast radius: which images ship openssl?
	inv := toolText(send("tools/call", map[string]any{"name": "query_inventory", "arguments": map[string]any{"name": "openssl"}}))
	m := inv["matches"].([]any)[0].(map[string]any)
	fmt.Printf("blast radius: %v image(s); first = %s owner=%s\n", inv["count"], m["image"], m["owner"])

	// 3. Explain a finding for the agent.
	ex := toolText(send("tools/call", map[string]any{"name": "explain_finding", "arguments": map[string]any{
		"rule_id": "DS-RAT-VULN-042", "severity": "critical", "remediation": "Upgrade openssl to 3.0.7"}}))
	fmt.Printf("explain: category=%s effort=%s\n", ex["category"], ex["effort"])

	// 4. Prioritized remediation plan (the security copilot).
	plan := toolText(send("tools/call", map[string]any{"name": "suggest_remediation", "arguments": map[string]any{"scan_id": firstScanID(st)}}))
	fmt.Printf("plan: %v action(s); #1 = %s\n", plan["total"], plan["actions"].([]any)[0].(map[string]any)["severity"])

	// Output:
	// tools available: 6
	// blast radius: 1 image(s); first = acme/api:1.2.3 owner=team-platform
	// explain: category=known-vulnerability effort=medium
	// plan: 1 action(s); #1 = CRITICAL
}

// firstScanID returns the id of the single seeded scan.
func firstScanID(st *store.Store) string { return st.Scans()[0].ID }
