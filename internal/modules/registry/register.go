package registry

import "github.com/Ratnadeepdeyroy/docker-security/internal/engine"

// Register adds the registry-security module to the registry. modules.Default()
// calls this during wiring; this package never edits the shared registry file.
func Register(r *engine.Registry) { r.Register(New()) }
