package mcp

import (
	"context"
	"encoding/json"
	"fmt"
)

// --- JSON-RPC 2.0 envelope ----------------------------------------------

// jsonrpcVersion is the only version we accept.
const jsonrpcVersion = "2.0"

// Standard JSON-RPC error codes (see the JSON-RPC 2.0 spec).
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// request is one inbound JSON-RPC message. A message with no ID is a
// notification and expects no response.
type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (r *request) isNotification() bool { return len(r.ID) == 0 }

// response is one outbound JSON-RPC message. Exactly one of Result/Error is set.
type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

// rpcError is a JSON-RPC error object.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *rpcError) Error() string { return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message) }

func errResult(id json.RawMessage, code int, msg string) *response {
	return &response{JSONRPC: jsonrpcVersion, ID: id, Error: &rpcError{Code: code, Message: msg}}
}

// handleMessage parses and dispatches a single JSON-RPC message and returns the
// bytes to write back. For a notification it returns (nil, nil): nothing is
// written. A malformed message yields a spec-compliant parse/invalid error.
func (s *Server) handleMessage(ctx context.Context, raw []byte) ([]byte, error) {
	var req request
	if err := json.Unmarshal(raw, &req); err != nil {
		return json.Marshal(errResult(nil, codeParseError, "parse error: "+err.Error()))
	}
	if req.JSONRPC != jsonrpcVersion {
		if req.isNotification() {
			return nil, nil
		}
		return json.Marshal(errResult(req.ID, codeInvalidRequest, "jsonrpc must be \"2.0\""))
	}

	resp := s.dispatch(ctx, &req)
	if req.isNotification() {
		// Notifications never get a response, even on error — we simply drop it.
		return nil, nil
	}
	return json.Marshal(resp)
}

// dispatch routes a request to its handler and builds a response.
func (s *Server) dispatch(ctx context.Context, req *request) *response {
	switch req.Method {
	case "initialize":
		return &response{JSONRPC: jsonrpcVersion, ID: req.ID, Result: s.initializeResult()}
	case "ping":
		return &response{JSONRPC: jsonrpcVersion, ID: req.ID, Result: map[string]any{}}
	case "notifications/initialized":
		return nil // notification; no response expected
	case "tools/list":
		return &response{JSONRPC: jsonrpcVersion, ID: req.ID, Result: s.listToolsResult()}
	case "tools/call":
		return s.callToolResult(ctx, req)
	default:
		return errResult(req.ID, codeMethodNotFound, "unknown method: "+req.Method)
	}
}

// initializeResult advertises our protocol version, capabilities, and identity.
func (s *Server) initializeResult() map[string]any {
	return map[string]any{
		"protocolVersion": protocolVersion,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]any{"name": serverName, "version": "phase9"},
		"instructions": "docker-security MCP server. Read-first: scan_target, get_findings, " +
			"explain_finding, query_inventory, suggest_remediation, list_modules. Mutating scan " +
			"persistence is off unless the operator enabled it.",
	}
}
