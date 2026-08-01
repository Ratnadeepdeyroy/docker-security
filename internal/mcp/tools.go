package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/store"
)

// --- Tool model ----------------------------------------------------------

// Tool is one MCP tool: its advertised schema plus a handler. Mutating tools are
// gated and audited by the caller (callToolResult); the handler itself just does
// the work.
type Tool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Mutating    bool
	Handler     func(ctx context.Context, s *Server, args json.RawMessage) (any, error)
}

// registerBuiltins installs the standard tool set in a deterministic order.
func (s *Server) registerBuiltins() {
	s.add(&Tool{
		Name:        "list_modules",
		Description: "List the security capability modules this engine exposes.",
		InputSchema: objSchema(nil, nil),
		Handler:     toolListModules,
	})
	s.add(&Tool{
		Name:        "scan_target",
		Description: "Analyze a Dockerfile, image, or filesystem path and return findings. Read-only unless 'persist' is set and mutations are enabled.",
		InputSchema: objSchema(map[string]any{
			"type":     prop("string", "target type: dockerfile | image | filesystem (auto-detected if omitted)"),
			"location": prop("string", "path or image reference"),
			"content":  prop("string", "inline content (e.g. a Dockerfile) instead of a path"),
			"modules":  arrProp("string", "restrict to these module names (default: all)"),
			"image":    prop("string", "canonical image identity for storage/grouping"),
			"persist":  prop("boolean", "store the result for later inventory/trend queries (mutating; requires mutations enabled)"),
		}, nil),
		Mutating: false, // scanning is read-only; persistence is checked at call time
		Handler:  toolScanTarget,
	})
	s.add(&Tool{
		Name:        "get_findings",
		Description: "Query stored findings across scanned images (requires a store). Filter by image, module, rule, owner, and minimum severity.",
		InputSchema: objSchema(map[string]any{
			"image":        prop("string", "restrict to one image"),
			"module":       prop("string", "restrict to one module"),
			"rule":         prop("string", "restrict to one rule id"),
			"owner":        prop("string", "restrict to findings owned by this team"),
			"min_severity": prop("string", "minimum severity: info|low|medium|high|critical"),
		}, nil),
		Handler: toolGetFindings,
	})
	s.add(&Tool{
		Name:        "query_inventory",
		Description: "Blast-radius query: which stored images contain a given component (optionally pinned to a version)? Requires a store.",
		InputSchema: objSchema(map[string]any{
			"name":    prop("string", "component name (case-insensitive)"),
			"version": prop("string", "exact version to pin (optional)"),
			"purl":    prop("string", "exact package URL to match (optional)"),
			"latest":  prop("boolean", "only consider each image's most recent scan"),
		}, []string{"name"}),
		Handler: toolQueryInventory,
	})
	s.add(&Tool{
		Name:        "explain_finding",
		Description: "Explain a finding for an agent: category, why it matters, machine-consumable remediation steps, effort, and framework mappings.",
		InputSchema: objSchema(map[string]any{
			"rule_id":     prop("string", "rule id, e.g. DS-RAT-VULN-001"),
			"module":      prop("string", "module name"),
			"severity":    prop("string", "severity name"),
			"title":       prop("string", "finding title"),
			"description": prop("string", "finding description"),
			"resource":    prop("string", "affected resource"),
			"remediation": prop("string", "remediation text to structure into steps"),
			"scan_id":     prop("string", "explain every finding of a stored scan instead of a single inline finding"),
		}, nil),
		Handler: toolExplainFinding,
	})
	s.add(&Tool{
		Name:        "suggest_remediation",
		Description: "Produce a prioritized, explained remediation plan for a stored scan or an inline set of findings (the security copilot).",
		InputSchema: objSchema(map[string]any{
			"scan_id": prop("string", "plan for a stored scan"),
			"target":  prop("string", "label for the plan when passing inline findings"),
			"findings": map[string]any{
				"type": "array", "description": "inline findings to plan for",
				"items": objSchema(map[string]any{
					"rule_id": prop("string", ""), "module": prop("string", ""),
					"severity": prop("string", ""), "title": prop("string", ""),
					"resource": prop("string", ""), "remediation": prop("string", ""),
				}, nil),
			},
		}, nil),
		Handler: toolSuggestRemediation,
	})
}

func (s *Server) add(t *Tool) {
	if _, ok := s.tools[t.Name]; !ok {
		s.order = append(s.order, t.Name)
	}
	s.tools[t.Name] = t
}

// --- tools/list ----------------------------------------------------------

func (s *Server) listToolsResult() map[string]any {
	tools := make([]map[string]any, 0, len(s.order))
	for _, name := range s.order {
		t := s.tools[name]
		tools = append(tools, map[string]any{
			"name": t.Name, "description": t.Description, "inputSchema": t.InputSchema,
		})
	}
	return map[string]any{"tools": tools}
}

// --- tools/call ----------------------------------------------------------

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// callToolResult runs a tool and wraps the outcome in MCP content. Tool-level
// failures (bad input, missing store) are returned as an MCP result with
// isError=true — the agent sees them as data, not a transport failure. Only
// protocol-shape problems become JSON-RPC errors.
func (s *Server) callToolResult(ctx context.Context, req *request) *response {
	var p callParams
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errResult(req.ID, codeInvalidParams, "invalid params: "+err.Error())
	}
	t, ok := s.tools[p.Name]
	if !ok {
		return errResult(req.ID, codeInvalidParams, "unknown tool: "+p.Name)
	}

	// Mutation gate: enforce and audit before doing any work.
	if t.Mutating {
		if !s.allowMutations {
			s.audit.record(s.now(), t.Name, false, req.Params, "denied: mutations disabled")
			return toolResult(req.ID, "mutation refused: this server runs read-only (enable mutations to allow "+t.Name+")", true)
		}
		s.audit.record(s.now(), t.Name, true, req.Params, "allowed")
	}

	out, err := t.Handler(ctx, s, p.Arguments)
	if err != nil {
		return toolResult(req.ID, "tool error: "+err.Error(), true)
	}
	text, mErr := json.MarshalIndent(out, "", "  ")
	if mErr != nil {
		return errResult(req.ID, codeInternalError, "marshal result: "+mErr.Error())
	}
	return toolResult(req.ID, string(text), false)
}

// toolResult builds a tools/call response with a single text content block.
func toolResult(id json.RawMessage, text string, isErr bool) *response {
	return &response{
		JSONRPC: jsonrpcVersion,
		ID:      id,
		Result: map[string]any{
			"content": []map[string]any{{"type": "text", "text": text}},
			"isError": isErr,
		},
	}
}

// --- Handlers ------------------------------------------------------------

func toolListModules(_ context.Context, s *Server, _ json.RawMessage) (any, error) {
	type mod struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Domains     []string `json:"domains"`
	}
	var out []mod
	for _, m := range s.reg.All() {
		out = append(out, mod{Name: m.Name(), Description: m.Description(), Domains: m.Domains()})
	}
	return map[string]any{"modules": out}, nil
}

type scanArgs struct {
	Type     string            `json:"type"`
	Location string            `json:"location"`
	Content  string            `json:"content"`
	Modules  []string          `json:"modules"`
	Image    string            `json:"image"`
	Labels   map[string]string `json:"labels"`
	Persist  bool              `json:"persist"`
}

func toolScanTarget(ctx context.Context, s *Server, raw json.RawMessage) (any, error) {
	var a scanArgs
	if err := unmarshalArgs(raw, &a); err != nil {
		return nil, err
	}
	if a.Content == "" && a.Location == "" {
		return nil, fmt.Errorf("scan_target needs a 'location' or inline 'content'")
	}

	// Persistence is a mutation. Gate and audit it here (scan itself is read-only).
	persist := a.Persist
	if persist {
		if !s.allowMutations {
			s.audit.record(s.now(), "scan_target:persist", false, raw, "denied: mutations disabled")
			persist = false
		} else if s.store == nil {
			return nil, fmt.Errorf("persist requested but no store is configured")
		} else {
			s.audit.record(s.now(), "scan_target:persist", true, raw, "allowed")
		}
	}

	// We only build the (potentially expensive) SBOM inventory when we are going
	// to store it — components exist to answer later inventory queries.
	withSBOM := persist
	target := buildTarget(a)
	sc := store.RunAndBuild(ctx, s.eng, target, a.Modules, a.Image, a.Labels, withSBOM, s.now())

	var scanID string
	if persist {
		id, err := s.store.Put(sc)
		if err != nil {
			return nil, fmt.Errorf("persist scan: %w", err)
		}
		scanID = id
	}

	return map[string]any{
		"target":     sc.Report.Target,
		"scan_id":    scanID,
		"persisted":  persist,
		"components": len(sc.Components),
		"counts":     s.counts(sc.Report),
		"findings":   sc.Report.Findings,
	}, nil
}

type findingsArgs struct {
	Image       string `json:"image"`
	Module      string `json:"module"`
	Rule        string `json:"rule"`
	Owner       string `json:"owner"`
	MinSeverity string `json:"min_severity"`
}

func toolGetFindings(_ context.Context, s *Server, raw json.RawMessage) (any, error) {
	if s.store == nil {
		return nil, fmt.Errorf("get_findings requires a store; none is configured")
	}
	var a findingsArgs
	if err := unmarshalArgs(raw, &a); err != nil {
		return nil, err
	}
	hits := s.store.QueryFindings(store.FindingQuery{
		Image: a.Image, Module: a.Module, RuleID: a.Rule, Owner: a.Owner,
		MinSeverity: engine.ParseSeverity(a.MinSeverity),
	})
	return map[string]any{"count": len(hits), "findings": hits}, nil
}

type inventoryArgs struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
	Latest  bool   `json:"latest"`
}

func toolQueryInventory(_ context.Context, s *Server, raw json.RawMessage) (any, error) {
	if s.store == nil {
		return nil, fmt.Errorf("query_inventory requires a store; none is configured")
	}
	var a inventoryArgs
	if err := unmarshalArgs(raw, &a); err != nil {
		return nil, err
	}
	matches := s.store.QueryComponent(store.ComponentQuery{
		Name: a.Name, Version: a.Version, PURL: a.PURL, LatestPerImage: a.Latest,
	})
	return map[string]any{"query": a.Name, "count": len(matches), "matches": matches}, nil
}

type explainArgs struct {
	ScanID      string `json:"scan_id"`
	RuleID      string `json:"rule_id"`
	Module      string `json:"module"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Remediation string `json:"remediation"`
}

func toolExplainFinding(_ context.Context, s *Server, raw json.RawMessage) (any, error) {
	var a explainArgs
	if err := unmarshalArgs(raw, &a); err != nil {
		return nil, err
	}
	// Scan mode: explain every finding of a stored scan.
	if a.ScanID != "" {
		if s.store == nil {
			return nil, fmt.Errorf("scan_id given but no store is configured")
		}
		sc, ok := s.store.Get(a.ScanID)
		if !ok {
			return nil, fmt.Errorf("scan %q not found", a.ScanID)
		}
		var out []Explanation
		for _, f := range sc.Report.Findings {
			out = append(out, Explain(f))
		}
		return map[string]any{"scan_id": a.ScanID, "count": len(out), "explanations": out}, nil
	}
	if a.RuleID == "" {
		return nil, fmt.Errorf("explain_finding needs a 'rule_id' or a 'scan_id'")
	}
	f := engine.Finding{
		RuleID: a.RuleID, Module: a.Module, Severity: engine.ParseSeverity(a.Severity),
		Title: a.Title, Description: a.Description, Resource: a.Resource, Remediation: a.Remediation,
	}
	return Explain(f), nil
}

type remediationArgs struct {
	ScanID   string `json:"scan_id"`
	Target   string `json:"target"`
	Findings []struct {
		RuleID      string `json:"rule_id"`
		Module      string `json:"module"`
		Severity    string `json:"severity"`
		Title       string `json:"title"`
		Resource    string `json:"resource"`
		Remediation string `json:"remediation"`
	} `json:"findings"`
}

func toolSuggestRemediation(_ context.Context, s *Server, raw json.RawMessage) (any, error) {
	var a remediationArgs
	if err := unmarshalArgs(raw, &a); err != nil {
		return nil, err
	}
	if a.ScanID != "" {
		if s.store == nil {
			return nil, fmt.Errorf("scan_id given but no store is configured")
		}
		sc, ok := s.store.Get(a.ScanID)
		if !ok {
			return nil, fmt.Errorf("scan %q not found", a.ScanID)
		}
		return BuildPlan(sc.Image, sc.Report.Findings), nil
	}
	if len(a.Findings) == 0 {
		return nil, fmt.Errorf("suggest_remediation needs a 'scan_id' or inline 'findings'")
	}
	fs := make([]engine.Finding, 0, len(a.Findings))
	for _, f := range a.Findings {
		fs = append(fs, engine.Finding{
			RuleID: f.RuleID, Module: f.Module, Severity: engine.ParseSeverity(f.Severity),
			Title: f.Title, Resource: f.Resource, Remediation: f.Remediation,
		})
	}
	target := a.Target
	if target == "" {
		target = "inline"
	}
	return BuildPlan(target, fs), nil
}

// --- shared helpers ------------------------------------------------------

// buildTarget mirrors the CLI/server target construction so a scan issued over
// MCP behaves identically to one issued over HTTP.
func buildTarget(a scanArgs) *engine.Target {
	tt := engine.TargetType(a.Type)
	if tt == "" {
		if a.Location != "" {
			tt = engine.DetectType(a.Location)
		} else {
			tt = engine.TargetDockerfile
		}
	}
	t := &engine.Target{Type: tt, Location: a.Location, Metadata: map[string]string{}}
	if a.Content != "" {
		t.Content = []byte(a.Content)
	}
	return t
}

func (s *Server) counts(r *engine.Report) map[string]int {
	c := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	for _, f := range r.Findings {
		c[f.Severity.String()]++
	}
	return c
}

// unmarshalArgs decodes tool arguments, tolerating the absent-arguments case
// (an omitted "arguments" member is a valid empty call).
func unmarshalArgs(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("invalid arguments: %w", err)
	}
	return nil
}

// --- JSON Schema helpers -------------------------------------------------

func objSchema(props map[string]any, required []string) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
	m := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func prop(typ, desc string) map[string]any {
	p := map[string]any{"type": typ}
	if desc != "" {
		p["description"] = desc
	}
	return p
}

func arrProp(itemType, desc string) map[string]any {
	return map[string]any{"type": "array", "description": desc, "items": map[string]any{"type": itemType}}
}
