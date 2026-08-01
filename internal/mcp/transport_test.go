package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPTransport_ToolCall(t *testing.T) {
	s := newTestServer(t)
	srv := httptest.NewServer(s.HTTPHandler())
	defer srv.Close()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"explain_finding","arguments":{"rule_id":"DS-RAT-SEC-001","severity":"critical"}}}`
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out response
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Error != nil {
		t.Fatalf("rpc error: %v", out.Error)
	}
	// The result text must carry the secret-exposure category.
	text := out.Result.(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "secret-exposure") {
		t.Errorf("explanation missing category: %s", text)
	}
}

func TestHTTPTransport_NotificationYields204(t *testing.T) {
	s := newTestServer(t)
	srv := httptest.NewServer(s.HTTPHandler())
	defer srv.Close()

	// No id ⇒ notification ⇒ no response body.
	body := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("notification status = %d, want 204", resp.StatusCode)
	}
}

func TestHTTPTransport_RejectsGET(t *testing.T) {
	s := newTestServer(t)
	srv := httptest.NewServer(s.HTTPHandler())
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", resp.StatusCode)
	}
}

func TestStdioTransport_NewlineDelimited(t *testing.T) {
	s := newTestServer(t)
	// Two messages: an initialize request (expects a response) and a bare
	// notification (expects none). Exactly one response line must come back.
	in := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
			`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	var out bytes.Buffer
	if err := s.ServeStdio(context.Background(), in, &out); err != nil {
		t.Fatalf("ServeStdio: %v", err)
	}
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("want exactly 1 response line, got %d:\n%s", len(lines), out.String())
	}
	var resp response
	if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	if resp.Result.(map[string]any)["protocolVersion"] != protocolVersion {
		t.Errorf("initialize response wrong: %v", resp.Result)
	}
}

func TestStdioTransport_ParseErrorIsReported(t *testing.T) {
	s := newTestServer(t)
	in := strings.NewReader("{not json}\n")
	var out bytes.Buffer
	if err := s.ServeStdio(context.Background(), in, &out); err != nil {
		t.Fatalf("ServeStdio: %v", err)
	}
	var resp response
	json.Unmarshal(out.Bytes(), &resp)
	if resp.Error == nil || resp.Error.Code != codeParseError {
		t.Errorf("want parse error, got %v", resp.Error)
	}
}
