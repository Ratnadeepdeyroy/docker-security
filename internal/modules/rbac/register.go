package rbac

import "github.com/Ratnadeepdeyroy/docker-security/internal/engine"

// Register adds the RBAC module to the registry. The master agent calls this
// from modules.Default() during integration, so this package never edits the
// shared registry file (parallel-safe wiring — see SHARED_CONTRACT §2).
func Register(r *engine.Registry) { r.Register(New()) }
