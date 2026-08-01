package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// MCPPush notifies a Model Context Protocol endpoint that a scan completed,
// delivering the report as a JSON-RPC 2.0 notification. It lets an agent runtime
// react to fresh scan results (open a ticket, kick off triage) without polling.
// It is a notification, not a request: fire-and-forget fits an outbound
// connector, and any 2xx (including 204 No Content) counts as delivered.
type MCPPush struct {
	Endpoint string // MCP HTTP endpoint, e.g. http://agent-host:7423/mcp
	// Method is the JSON-RPC notification method; defaults to
	// "notifications/scan_completed".
	Method string
	Client *http.Client
}

// NewMCPPush builds an MCP push connector with defaults.
func NewMCPPush(endpoint string) *MCPPush {
	return &MCPPush{
		Endpoint: endpoint,
		Method:   "notifications/scan_completed",
		Client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func (m *MCPPush) Name() string { return "mcp-push" }

func (m *MCPPush) Send(ctx context.Context, r *engine.Report) error {
	method := m.Method
	if method == "" {
		method = "notifications/scan_completed"
	}
	// A JSON-RPC 2.0 notification: no "id" member, so the peer sends no response.
	msg := map[string]any{
		"jsonrpc": "2.0",
		"method":  method,
		"params": map[string]any{
			"target": r.Target,
			"counts": counts(r),
			"report": r,
		},
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "docker-security")

	resp, err := m.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("mcp endpoint returned %s", resp.Status)
	}
	return nil
}

// counts renders a severity tally for the notification payload.
func counts(r *engine.Report) map[string]int {
	c := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	for _, f := range r.Findings {
		c[f.Severity.String()]++
	}
	return c
}

func (m *MCPPush) client() *http.Client {
	if m.Client != nil {
		return m.Client
	}
	return http.DefaultClient
}
