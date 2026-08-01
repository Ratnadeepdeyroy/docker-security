package mcp

import (
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/store"
)

func TestMutationGate_DeniedByDefault(t *testing.T) {
	st := store.NewMemory()
	s := newTestServer(t, WithStore(st)) // mutations off (default)

	out, isErr := callTool(t, s, "scan_target", map[string]any{
		"type": "dockerfile", "content": "FROM x", "image": "img", "persist": true,
	})
	if isErr {
		t.Fatalf("scan itself should succeed (read-only): %v", out)
	}
	if out["persisted"].(bool) {
		t.Error("persist must be refused when mutations are disabled")
	}
	if st.Len() != 0 {
		t.Errorf("store was written despite mutations being off: len=%d", st.Len())
	}
	// The refusal is audited.
	entries := s.Audit().Entries()
	if len(entries) != 1 || entries[0].Allowed {
		t.Fatalf("expected one denied audit entry, got %+v", entries)
	}
	if entries[0].Time != fixedClock() {
		t.Errorf("audit timestamp not from injected clock: %v", entries[0].Time)
	}
}

func TestMutationGate_AllowedWhenEnabled(t *testing.T) {
	st := store.NewMemory()
	s := newTestServer(t, WithStore(st), WithMutations(true))

	out, isErr := callTool(t, s, "scan_target", map[string]any{
		"type": "dockerfile", "content": "FROM x", "image": "img", "persist": true,
	})
	if isErr {
		t.Fatalf("scan_target error: %v", out)
	}
	if !out["persisted"].(bool) || out["scan_id"] == "" {
		t.Fatalf("expected persisted scan with id, got %v", out)
	}
	if st.Len() != 1 {
		t.Errorf("store should hold 1 scan, got %d", st.Len())
	}
	entries := s.Audit().Entries()
	if len(entries) != 1 || !entries[0].Allowed {
		t.Fatalf("expected one allowed audit entry, got %+v", entries)
	}
	// The audit records a digest, never the raw arguments.
	if entries[0].ArgsDigest == "" || len(entries[0].ArgsDigest) != 16 {
		t.Errorf("audit should carry a 16-char args digest, got %q", entries[0].ArgsDigest)
	}
}
