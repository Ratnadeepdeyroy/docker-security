package runtime

import (
	"path"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// This file implements the novel AI-age detection: catching a *containerized AI
// agent* that has gone rogue. As agents gain shell/tool access and network
// egress, prompt injection turns "summarize this document" into "exfiltrate the
// service-account token". Incumbent runtime sensors do not yet model this threat
// class. We do — deterministically, keyed off a workload declared to be an AI
// agent (image label / deploy annotation → Container.AIAgent).
//
// It is OFF BY DEFAULT (Options.EnableAgentRuntime) and only ever inspects
// workloads explicitly marked as agents, so it never touches ordinary traffic
// and never gates correctness. The signal core is deterministic; a reasoning
// layer can enrich it later (parked in NOTES.md).

// --- DS-RAT-RT-100 AI agent runtime abuse ------------------------------------

type agentRuntimeRule struct {
	ruleBase
	enabled bool
}

func newAgentRuntimeRule(opts Options) Rule {
	return &agentRuntimeRule{
		ruleBase: ruleBase{
			id: "DS-RAT-RT-100",
			info: RuleInfo{
				Title:       "AI agent runtime abuse (rogue agent / prompt-injection)",
				Severity:    engine.SeverityHigh,
				Technique:   techPromptInject,
				Default:     false,
				Description: "A workload declared to be an AI/LLM agent performed an action characteristic of a hijacked agent: spawning an unexpected shell or tool, executing a prompt-injection-style command, or egressing to an unknown/model endpoint. This is agent-hijacking — a threat class traditional runtime sensors do not model.",
				Remediation: "Sandbox agent tool-use behind an allowlist of commands and endpoints. Require human approval for shell/network tools. Log prompts and tool calls. Treat unexpected agent egress or exec as a prompt-injection incident.",
			},
		},
		enabled: opts.EnableAgentRuntime,
	}
}

func (r *agentRuntimeRule) Evaluate(ev *Event, st *State) []Detection {
	if !r.enabled || !ev.Container.AIAgent {
		return nil // off by default; only ever looks at declared agents
	}
	switch ev.Kind {
	case KindProcess:
		// An agent spawning a shell/tool it was not expected to. Prompt-injection
		// payloads in argv are an especially strong signal.
		if sig, ok := injectionPayload(ev.Process.Args); ok {
			return []Detection{r.fire(ev, "AI agent executed injection-style payload ("+sig+", pid "+itoa(ev.Process.PID)+")",
				agentMeta(ev, "prompt-injection-exec", sig))}
		}
		if isShell(ev.Process.Exe, ev.Process.Comm) && !shellIsEntrypoint(ev.Process.Ancestry) {
			return []Detection{r.fire(ev, "AI agent spawned an unexpected shell "+ev.Process.Exe+" (pid "+itoa(ev.Process.PID)+")",
				agentMeta(ev, "unexpected-shell", path.Base(ev.Process.Exe)))}
		}
		if isEscalationTool(ev.Process.Exe) {
			return []Detection{r.fire(ev, "AI agent invoked a privileged tool "+path.Base(ev.Process.Exe)+" (pid "+itoa(ev.Process.PID)+")",
				agentMeta(ev, "unexpected-tool", path.Base(ev.Process.Exe)))}
		}
	case KindNetwork:
		if ev.Network == nil || ev.Network.Op != "connect" {
			return nil
		}
		// Egress to an endpoint that is neither a known model provider nor
		// otherwise expected — a hijacked agent phoning home or exfiltrating.
		if !isKnownModelEndpoint(ev.Network) {
			ep := endpointKey(ev.Network)
			if st.markConnect(containerKey(ev.Container)+"|agent", ep) {
				return []Detection{r.fire(ev, "AI agent egress to unrecognized endpoint "+ep+" (not a known model/tool provider)",
					agentMeta(ev, "unknown-egress", ep))}
			}
		}
	}
	return nil
}

// injectionPayload reports whether argv looks like a prompt-injection outcome:
// a reverse shell, a download piped into a shell, or a dynamic command-exec
// primitive. These are the shapes "ignore your instructions and run this" turns
// into once an agent has a shell/tool. Broader than reverseShellPayload because
// an injected agent more often runs `curl … | sh` than a raw reverse shell.
func injectionPayload(args []string) (string, bool) {
	if sig, ok := reverseShellPayload(args); ok {
		return sig, true
	}
	joined := strings.ToLower(strings.Join(args, " "))
	for _, sig := range []string{
		"| sh", "|sh", "| bash", "|bash", "curl -s", "wget -q",
		"os.system(", "subprocess.", "eval(", "exec(", "base64 -d",
	} {
		if strings.Contains(joined, sig) {
			return strings.TrimSpace(sig), true
		}
	}
	return "", false
}

// agentMeta builds the structured detail carried on an agent detection.
func agentMeta(ev *Event, signal, value string) map[string]string {
	return map[string]string{
		"agent_signal": signal,
		"value":        value,
		"image":        ev.Container.ImageRef,
	}
}

// isEscalationTool flags tools an autonomous agent should essentially never run.
func isEscalationTool(exe string) bool {
	switch path.Base(exe) {
	case "nmap", "nc", "ncat", "socat", "tcpdump", "kubectl", "docker", "aws", "gcloud", "az":
		return true
	}
	return false
}

// isKnownModelEndpoint reports whether an egress target is a recognized LLM/tool
// provider. The list is intentionally conservative; anything else from an agent
// is worth surfacing. Operators extend expected egress via the DS-RAT-RT-007
// allowlist rather than here.
func isKnownModelEndpoint(n *NetworkEvent) bool {
	d := strings.ToLower(n.Domain)
	if d == "" {
		return false
	}
	for _, known := range []string{
		"api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com",
		"bedrock.amazonaws.com", "api.cohere.ai", "api.mistral.ai",
	} {
		if d == known || strings.HasSuffix(d, "."+known) {
			return true
		}
	}
	return false
}
