// Package plugin runs third-party analyzers out of process, so the community
// (and other AI tools) can extend detection without forking or being linked into
// the binary. A plugin is any executable that speaks a tiny JSON protocol over
// stdin/stdout; a JSON manifest declares its name, the target types it handles,
// and how to launch it. The host adapts each plugin to the engine.Module
// interface, so a loaded plugin appears in the CLI, HTTP API, and MCP server
// exactly like a built-in module.
//
// Out-of-process is a deliberate isolation boundary. A plugin cannot corrupt the
// engine's memory, and a plugin that hangs, crashes, or floods stdout is
// contained: every run is time-bounded (context), output-bounded (a hard byte
// cap), launched with no shell and a scrubbed environment, and any failure is
// recorded as a module error rather than taking down the scan.
//
// WASM and gRPC transports were considered for stronger sandboxing but both need
// a third-party runtime; per the project's zero-dependency rule they are parked
// (see NOTES.md). The subprocess protocol is the stdlib-only design that still
// delivers real isolation today.
package plugin

import (
	"context"
	"fmt"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// protocolVersion is sent on every request and echoed by well-behaved plugins.
const protocolVersion = "docker-security.plugin/v1"

// defaultTimeoutMS bounds a single Analyze call when the manifest does not.
const defaultTimeoutMS = 10_000

// Manifest declares a plugin's identity and how to launch it. It is plain JSON
// so a plugin author writes it by hand. Any Exec element containing the token
// ${dir} has it replaced with the manifest's directory, so a manifest can point
// at a script shipped alongside it without hard-coding an absolute path.
type Manifest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Version     string   `json:"version,omitempty"`
	Domains     []string `json:"domains,omitempty"`
	// TargetTypes lists the engine target types this plugin handles, e.g.
	// ["dockerfile","filesystem"]. Empty means it handles none (inert).
	TargetTypes []string `json:"target_types,omitempty"`
	// Exec is the argv used to launch the plugin: the command followed by its
	// arguments. It is executed directly (no shell), so nothing is interpolated.
	Exec []string `json:"exec"`
	// TimeoutMS bounds one Analyze call. Zero uses defaultTimeoutMS.
	TimeoutMS int `json:"timeout_ms,omitempty"`

	// dir is the manifest's directory, filled in on load for ${dir} resolution.
	dir string
}

// --- Wire protocol -------------------------------------------------------

// pluginRequest is what the host writes to a plugin's stdin.
type pluginRequest struct {
	Protocol string     `json:"protocol"`
	Target   wireTarget `json:"target"`
}

type wireTarget struct {
	Type          string            `json:"type"`
	Location      string            `json:"location"`
	ContentBase64 string            `json:"content_base64,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// pluginResponse is what the host reads from a plugin's stdout. Severity is a
// string so plugin authors need not know our internal enum; the host maps it via
// engine.ParseSeverity.
type pluginResponse struct {
	Findings []wireFinding `json:"findings"`
	Error    string        `json:"error,omitempty"`
}

type wireFinding struct {
	RuleID      string            `json:"rule_id"`
	Severity    string            `json:"severity"`
	Title       string            `json:"title"`
	Description string            `json:"description,omitempty"`
	Resource    string            `json:"resource,omitempty"`
	Remediation string            `json:"remediation,omitempty"`
	References  []string          `json:"references,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Location    *engine.Location  `json:"location,omitempty"`
}

// --- Plugin (engine.Module adapter) --------------------------------------

// Plugin adapts one manifested executable to the engine.Module interface.
type Plugin struct {
	manifest Manifest
	argv     []string // resolved Exec (${dir} expanded)
	runner   runner   // seam for tests; production uses execRunner
}

// runner executes the plugin process with a request and returns raw stdout. It
// is an interface so tests can substitute an in-process fake.
type runner interface {
	run(ctx context.Context, argv []string, timeoutMS int, stdin []byte) ([]byte, error)
}

// Name, Description, Domains satisfy engine.Module from the manifest.
func (p *Plugin) Name() string        { return p.manifest.Name }
func (p *Plugin) Description() string { return p.manifest.Description }
func (p *Plugin) Domains() []string   { return p.manifest.Domains }
func (p *Plugin) Manifest() Manifest  { return p.manifest }

// Supports reports whether the plugin declared this target type.
func (p *Plugin) Supports(tt engine.TargetType) bool {
	for _, t := range p.manifest.TargetTypes {
		if engine.TargetType(t) == tt {
			return true
		}
	}
	return false
}

// Analyze runs the plugin subprocess and projects its findings. Any failure —
// launch error, timeout, oversized or malformed output, or a plugin-reported
// error — is returned so the engine records it as a module error; it never
// panics the run. The plugin's declared name is stamped onto every finding so a
// plugin cannot impersonate another module.
func (p *Plugin) Analyze(ctx context.Context, t *engine.Target) ([]engine.Finding, error) {
	req := pluginRequest{Protocol: protocolVersion, Target: toWireTarget(t)}
	stdin, err := marshalRequest(req)
	if err != nil {
		return nil, fmt.Errorf("plugin %q: encode request: %w", p.manifest.Name, err)
	}
	out, err := p.runner.run(ctx, p.argv, p.timeoutMS(), stdin)
	if err != nil {
		return nil, fmt.Errorf("plugin %q: %w", p.manifest.Name, err)
	}
	resp, err := parseResponse(out)
	if err != nil {
		return nil, fmt.Errorf("plugin %q: %w", p.manifest.Name, err)
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("plugin %q reported: %s", p.manifest.Name, resp.Error)
	}
	return p.project(resp.Findings), nil
}

func (p *Plugin) timeoutMS() int {
	if p.manifest.TimeoutMS > 0 {
		return p.manifest.TimeoutMS
	}
	return defaultTimeoutMS
}

// project converts wire findings to engine findings, forcing Module to the
// plugin name and defaulting a missing rule id so output is always attributable.
func (p *Plugin) project(ws []wireFinding) []engine.Finding {
	out := make([]engine.Finding, 0, len(ws))
	for i, w := range ws {
		ruleID := strings.TrimSpace(w.RuleID)
		if ruleID == "" {
			ruleID = fmt.Sprintf("DS-RAT-PLUGIN-%s-%03d", strings.ToUpper(sanitize(p.manifest.Name)), i+1)
		}
		out = append(out, engine.Finding{
			RuleID:      ruleID,
			Module:      p.manifest.Name, // authoritative: plugins cannot spoof another module
			Severity:    engine.ParseSeverity(w.Severity),
			Title:       w.Title,
			Description: w.Description,
			Resource:    w.Resource,
			Location:    w.Location,
			Remediation: w.Remediation,
			References:  w.References,
			Metadata:    w.Metadata,
		})
	}
	return out
}

// sanitize keeps a name safe for use inside a generated rule id.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}
