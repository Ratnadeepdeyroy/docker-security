package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// --- AI-age feature: attested agent actions ---------------------------------
//
// This is the phase's AI-age leap, and it is off by default: nothing in the
// deterministic verify path requires it, and no attestation is produced unless a
// caller explicitly builds one. As software infrastructure is increasingly
// changed by autonomous agents, "a human approved this build" is no longer the
// only provenance that matters. An agent-action attestation records *which*
// agent (model + version), acting on *which* instruction (a prompt hash, never
// the raw prompt — prompts may hold secrets), used *which* tool to produce
// *which* artifact. Verified against the same trust root as any other
// attestation, it gives an audit trail for automation: after an incident you can
// ask "did an agent touch this image, and under what instruction?" and get a
// cryptographically signed answer.
//
// The prompt is deliberately reduced to a hash. Storing prompts verbatim in a
// signed, widely distributed attestation would be a data-exfiltration hazard;
// the hash still lets you prove a later-disclosed prompt matches what ran.

// AgentAction is the predicate for an attested automated action.
type AgentAction struct {
	Agent     Agent      `json:"agent"`
	Prompt    PromptRef  `json:"prompt"`
	Action    ActionInfo `json:"action"`
	Timestamp time.Time  `json:"timestamp"`
}

// Agent identifies the automated actor.
type Agent struct {
	// ID is a stable identifier for the agent/automation (e.g.
	// "ci-bot@corp.example" or a service account).
	ID string `json:"id"`
	// Model names the model that drove the agent, if any (e.g. "claude-opus-4").
	Model string `json:"model,omitempty"`
	// Version is the agent software version.
	Version string `json:"version,omitempty"`
}

// PromptRef references the instruction the agent acted on, by hash.
type PromptRef struct {
	// SHA256 is the hex SHA-256 of the exact prompt/instruction bytes.
	SHA256 string `json:"sha256"`
	// Summary is an optional short, non-sensitive human description.
	Summary string `json:"summary,omitempty"`
}

// ActionInfo describes what the agent did.
type ActionInfo struct {
	// Type is the action class (e.g. "build", "deploy", "patch", "config-change").
	Type string `json:"type"`
	// Tool is the tool or API the agent invoked.
	Tool string `json:"tool,omitempty"`
	// Target is what the action affected (e.g. an image ref or resource name).
	Target string `json:"target,omitempty"`
}

// HashPrompt returns the hex SHA-256 of a prompt's bytes, the value to store in
// PromptRef.SHA256. Callers hash the prompt themselves rather than passing it
// here-then-elsewhere, so the raw prompt never lingers in the attestation.
func HashPrompt(prompt []byte) string {
	sum := sha256.Sum256(prompt)
	return hex.EncodeToString(sum[:])
}

// NewAgentActionStatement builds a signed-ready in-toto statement attesting that
// an agent produced the artifact identified by subjectDigest. It validates that
// the prompt hash is a well-formed SHA-256 so a caller cannot accidentally emit
// an attestation with an empty or bogus prompt reference.
func NewAgentActionStatement(subjectName, subjectDigest string, action AgentAction) (*Statement, error) {
	if len(action.Prompt.SHA256) != 64 {
		return nil, fmt.Errorf("agent action: prompt sha256 must be 64 hex chars, got %d", len(action.Prompt.SHA256))
	}
	if _, err := hex.DecodeString(action.Prompt.SHA256); err != nil {
		return nil, fmt.Errorf("agent action: prompt sha256 is not hex: %w", err)
	}
	if action.Agent.ID == "" {
		return nil, fmt.Errorf("agent action: agent id is required")
	}
	return NewStatement(subjectName, subjectDigest, PredicateAgentAction, action)
}
