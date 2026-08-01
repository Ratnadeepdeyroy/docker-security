package attest

import (
	"testing"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/sig"
)

// TestAgentActionAttestation exercises the AI-age feature end to end: build a
// signed agent-action attestation, verify it against a trust root, and read the
// predicate back. This is the "it is real, tested, off by default" evidence:
// producing one is an explicit call, and the verify path treats it like any
// other attestation (same trust root, same anti-replay checks).
func TestAgentActionAttestation(t *testing.T) {
	signer := mustSigner(t, "agent")

	prompt := []byte("rebuild the base image with the latest security patches")
	action := AgentAction{
		Agent:     Agent{ID: "ci-bot@corp.example", Model: "claude-opus-4", Version: "1.2.0"},
		Prompt:    PromptRef{SHA256: HashPrompt(prompt), Summary: "patch base image"},
		Action:    ActionInfo{Type: "build", Tool: "dsecrat", Target: "app:latest"},
		Timestamp: time.Unix(1700000000, 0).UTC(),
	}
	st, err := NewAgentActionStatement("app", testDigest, action)
	if err != nil {
		t.Fatalf("NewAgentActionStatement: %v", err)
	}
	env, err := Sign(st, signer)
	if err != nil {
		t.Fatal(err)
	}

	trust := trustOf(t, signer, "ci-bot@corp.example")
	res, err := Verify(env, trust, Requirement{
		ExpectedDigest: testDigest,
		PredicateType:  PredicateAgentAction,
		Policy:         sig.Policy{Identities: []string{"ci-bot@corp.example"}},
	})
	if err != nil {
		t.Fatalf("Verify agent action: %v", err)
	}

	var got AgentAction
	if err := res.Statement.DecodePredicate(&got); err != nil {
		t.Fatal(err)
	}
	if got.Prompt.SHA256 != HashPrompt(prompt) {
		t.Errorf("prompt hash mismatch")
	}
	if got.Agent.Model != "claude-opus-4" {
		t.Errorf("agent model lost: %q", got.Agent.Model)
	}
	// The raw prompt must never appear in the attestation bytes.
	data, _ := st.Marshal()
	if contains(data, prompt) {
		t.Error("raw prompt leaked into the agent-action attestation")
	}
}

func TestAgentActionRejectsBadPromptHash(t *testing.T) {
	action := AgentAction{
		Agent:  Agent{ID: "bot"},
		Prompt: PromptRef{SHA256: "short"},
	}
	if _, err := NewAgentActionStatement("app", testDigest, action); err == nil {
		t.Error("accepted an agent action with a malformed prompt hash")
	}
}

func TestAgentActionRequiresAgentID(t *testing.T) {
	action := AgentAction{Prompt: PromptRef{SHA256: HashPrompt([]byte("x"))}}
	if _, err := NewAgentActionStatement("app", testDigest, action); err == nil {
		t.Error("accepted an agent action with no agent id")
	}
}

func contains(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
