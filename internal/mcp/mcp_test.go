package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/store"
)

// fakeModule returns one finding for any target, so MCP tests exercise the real
// scan path without importing a capability package.
type fakeModule struct{}

func (fakeModule) Name() string                    { return "fake" }
func (fakeModule) Description() string             { return "test module" }
func (fakeModule) Domains() []string               { return []string{"0"} }
func (fakeModule) Supports(engine.TargetType) bool { return true }
func (fakeModule) Analyze(context.Context, *engine.Target) ([]engine.Finding, error) {
	return []engine.Finding{{
		RuleID: "DS-RAT-DF-001", Module: "fake", Severity: engine.SeverityHigh,
		Title: "Base image pinned to :latest", Remediation: "Pin the base image by digest",
	}}, nil
}

func fixedClock() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }

func newTestServer(t *testing.T, opts ...Option) *Server {
	t.Helper()
	reg := engine.NewRegistry()
	reg.Register(fakeModule{})
	opts = append([]Option{WithClock(fixedClock)}, opts...)
	return New(reg, opts...)
}

// call is a helper that sends one JSON-RPC message and decodes the response.
func call(t *testing.T, s *Server, method string, params any) response {
	t.Helper()
	var raw json.RawMessage
	if params != nil {
		b, _ := json.Marshal(params)
		raw = b
	}
	req := request{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: method, Params: raw}
	reqBytes, _ := json.Marshal(req)
	respBytes, err := s.handleMessage(context.Background(), reqBytes)
	if err != nil {
		t.Fatalf("handleMessage(%s): %v", method, err)
	}
	var resp response
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

// callTool invokes tools/call and returns the decoded text content and isError.
func callTool(t *testing.T, s *Server, name string, args any) (map[string]any, bool) {
	t.Helper()
	resp := call(t, s, "tools/call", map[string]any{"name": name, "arguments": args})
	if resp.Error != nil {
		t.Fatalf("tools/call %s protocol error: %v", name, resp.Error)
	}
	result := resp.Result.(map[string]any)
	isErr, _ := result["isError"].(bool)
	content := result["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		// suggest_remediation / explain return objects; but on tool error the text
		// is a plain string — return it under "_error".
		return map[string]any{"_text": text}, isErr
	}
	return out, isErr
}

func TestInitialize(t *testing.T) {
	s := newTestServer(t)
	resp := call(t, s, "initialize", map[string]any{"protocolVersion": "2024-11-05"})
	if resp.Error != nil {
		t.Fatalf("initialize error: %v", resp.Error)
	}
	res := resp.Result.(map[string]any)
	if res["protocolVersion"] != protocolVersion {
		t.Errorf("protocolVersion = %v, want %s", res["protocolVersion"], protocolVersion)
	}
}

func TestToolsList(t *testing.T) {
	s := newTestServer(t)
	resp := call(t, s, "tools/list", nil)
	tools := resp.Result.(map[string]any)["tools"].([]any)
	if len(tools) != 6 {
		t.Fatalf("want 6 tools, got %d", len(tools))
	}
	// First tool is list_modules (deterministic registration order).
	if tools[0].(map[string]any)["name"] != "list_modules" {
		t.Errorf("first tool = %v, want list_modules", tools[0].(map[string]any)["name"])
	}
}

func TestScanTargetRoundTrip(t *testing.T) {
	s := newTestServer(t)
	out, isErr := callTool(t, s, "scan_target", map[string]any{
		"type": "dockerfile", "content": "FROM ubuntu:latest", "location": "Dockerfile",
	})
	if isErr {
		t.Fatalf("scan_target returned error: %v", out)
	}
	findings := out["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	if findings[0].(map[string]any)["rule_id"] != "DS-RAT-DF-001" {
		t.Errorf("unexpected finding: %v", findings[0])
	}
	if out["persisted"].(bool) {
		t.Error("scan should not persist without persist=true")
	}
}

func TestExplainFinding(t *testing.T) {
	s := newTestServer(t)
	out, isErr := callTool(t, s, "explain_finding", map[string]any{
		"rule_id": "DS-RAT-VULN-001", "severity": "critical", "title": "openssl CVE",
		"remediation": "Upgrade openssl to 3.0.7; rebuild the image",
	})
	if isErr {
		t.Fatalf("explain returned error: %v", out)
	}
	if out["category"] != "known-vulnerability" {
		t.Errorf("category = %v, want known-vulnerability", out["category"])
	}
	steps := out["remediation"].([]any)
	if len(steps) != 2 {
		t.Errorf("want 2 remediation steps parsed, got %d: %v", len(steps), steps)
	}
}

func TestSuggestRemediationOrdersBySeverity(t *testing.T) {
	s := newTestServer(t)
	out, isErr := callTool(t, s, "suggest_remediation", map[string]any{
		"target": "img",
		"findings": []map[string]any{
			{"rule_id": "DS-RAT-DF-002", "severity": "low", "title": "low issue"},
			{"rule_id": "DS-RAT-VULN-9", "severity": "critical", "title": "crit issue"},
		},
	})
	if isErr {
		t.Fatalf("plan error: %v", out)
	}
	actions := out["actions"].([]any)
	if len(actions) != 2 {
		t.Fatalf("want 2 actions, got %d", len(actions))
	}
	first := actions[0].(map[string]any)
	if first["severity"] != "CRITICAL" || first["priority"].(float64) != 1 {
		t.Errorf("critical must be priority 1, got %v", first)
	}
}

func TestStoreBackedTools(t *testing.T) {
	st := store.NewMemory()
	sc := &store.Scan{
		Image:      "api",
		RecordedAt: fixedClock(),
		Labels:     map[string]string{"owner": "team-a"},
		Report: &engine.Report{Target: "api", Findings: []engine.Finding{
			{RuleID: "DS-RAT-VULN-1", Module: "vuln", Severity: engine.SeverityCritical, Title: "cve"},
		}},
		Components: []store.Component{{Name: "openssl", Version: "3.0.1"}},
	}
	if _, err := st.Put(sc); err != nil {
		t.Fatalf("seed store: %v", err)
	}
	s := newTestServer(t, WithStore(st))

	// get_findings
	gf, isErr := callTool(t, s, "get_findings", map[string]any{"min_severity": "high"})
	if isErr || gf["count"].(float64) != 1 {
		t.Fatalf("get_findings failed: err=%v out=%v", isErr, gf)
	}

	// query_inventory (blast radius)
	qi, isErr := callTool(t, s, "query_inventory", map[string]any{"name": "openssl", "version": "3.0.1"})
	if isErr || qi["count"].(float64) != 1 {
		t.Fatalf("query_inventory failed: err=%v out=%v", isErr, qi)
	}
	matches := qi["matches"].([]any)
	if matches[0].(map[string]any)["image"] != "api" {
		t.Errorf("blast radius should find api, got %v", matches[0])
	}
}

func TestStoreToolsFailClosedWithoutStore(t *testing.T) {
	s := newTestServer(t) // no store
	out, isErr := callTool(t, s, "query_inventory", map[string]any{"name": "x"})
	if !isErr {
		t.Errorf("query_inventory should error without a store; got %v", out)
	}
}

func TestUnknownMethodAndTool(t *testing.T) {
	s := newTestServer(t)
	resp := call(t, s, "does/not/exist", nil)
	if resp.Error == nil || resp.Error.Code != codeMethodNotFound {
		t.Errorf("want method-not-found, got %v", resp.Error)
	}
	// Unknown tool → invalid params error result.
	bad := call(t, s, "tools/call", map[string]any{"name": "nope", "arguments": map[string]any{}})
	if bad.Error == nil {
		t.Errorf("unknown tool should yield an error, got %v", bad.Result)
	}
}
