package attacksim

import "github.com/Ratnadeepdeyroy/docker-security/internal/engine"

// Register adds the attack-sim module to the registry. The master agent calls
// this from modules.Default() during integration, so this package never edits
// the shared registry file (parallel-safe wiring — see SHARED_CONTRACT §2).
//
// Registering the module is safe even though it performs adversary emulation:
// the module is inert unless a target explicitly carries the authorization
// acknowledgement in its metadata (see attacksim.go).
func Register(r *engine.Registry) { r.Register(New()) }
