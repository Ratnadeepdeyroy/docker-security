package runtime

import "github.com/Ratnadeepdeyroy/docker-security/internal/engine"

// Register adds the runtime module to the registry. The master agent calls this
// from modules.Default() during integration, so this package never edits the
// shared registry file (parallel-safe wiring — see SHARED_CONTRACT §2).
//
// Registering is safe: without runtime telemetry supplied in the target the
// module produces nothing, and the behavioral/agent rules stay off unless
// explicitly enabled via metadata.
func Register(r *engine.Registry) { r.Register(New()) }
