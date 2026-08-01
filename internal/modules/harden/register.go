package harden

import "github.com/Ratnadeepdeyroy/docker-security/internal/engine"

// Register adds the harden module to the registry with its default
// (deterministic baseline) configuration. The master agent calls this from
// modules.Default() during integration; per SHARED_CONTRACT §2 this package never
// edits the shared registry file itself. See NOTES.md for the one-line wiring.
//
// To enable the off-by-default agent-appliable hardening bundle in a given
// frontend, register a configured instance instead:
//
//	r.Register(harden.New(harden.WithHardeningBundle()))
func Register(r *engine.Registry) { r.Register(New()) }

// Compile-time assurance that Module satisfies the engine contract.
var _ engine.Module = (*Module)(nil)
