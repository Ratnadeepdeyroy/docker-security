// Package mcp implements a Model Context Protocol server that exposes the
// docker-security engine to AI agents. MCP is JSON-RPC 2.0; this package speaks
// the protocol directly over stdio (newline-delimited messages) and HTTP, with
// no SDK dependency — the wire format is small and implementing it ourselves
// keeps the zero-dependency posture.
//
// The design is read-first. Every tool that only inspects (scan_target,
// get_findings, explain_finding, query_inventory, suggest_remediation,
// list_modules) is always available. The single mutating capability — persisting
// a scan into the store — is off by default, gated behind WithMutations, and
// every attempt (allowed or denied) is written to an audit log. An agent can
// reason about security posture freely; it cannot quietly change state.
//
// The server is generic over engine.Registry: it exposes whatever modules the
// caller registered. It never imports capability modules, so the same server
// serves a one-module or a twenty-module engine unchanged.
package mcp

import (
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/store"
)

// protocolVersion is the MCP revision we implement. Clients send their own in
// initialize; we echo a version we support.
const protocolVersion = "2024-11-05"

const serverName = "docker-security"

// Server is an MCP endpoint over the engine. Construct with New and drive it via
// ServeStdio or HTTPHandler.
type Server struct {
	reg   *engine.Registry
	eng   *engine.Engine
	store *store.Store // optional: enables get_findings / query_inventory
	tools map[string]*Tool
	order []string // tool registration order, for deterministic tools/list

	allowMutations bool
	audit          *AuditLog
	now            func() time.Time
}

// Option configures a Server.
type Option func(*Server)

// WithStore attaches a scan store, enabling the inventory-backed tools
// (get_findings, query_inventory) and scan persistence.
func WithStore(s *store.Store) Option { return func(sv *Server) { sv.store = s } }

// WithMutations enables state-changing tool behaviour (scan persistence). Off by
// default: an agent gets a read-only surface unless the operator opts in.
func WithMutations(on bool) Option { return func(sv *Server) { sv.allowMutations = on } }

// WithClock injects the time source used for audit timestamps, for deterministic
// tests. Analysis itself never reads this — only the audit trail does.
func WithClock(fn func() time.Time) Option { return func(sv *Server) { sv.now = fn } }

// New builds an MCP server exposing the given module registry.
func New(reg *engine.Registry, opts ...Option) *Server {
	s := &Server{
		reg:   reg,
		eng:   engine.New(reg),
		tools: map[string]*Tool{},
		audit: NewAuditLog(),
		now:   func() time.Time { return time.Now().UTC() },
	}
	for _, o := range opts {
		o(s)
	}
	s.registerBuiltins()
	return s
}

// Audit exposes the audit log so an operator (or a test) can inspect what
// mutating calls were attempted.
func (s *Server) Audit() *AuditLog { return s.audit }
