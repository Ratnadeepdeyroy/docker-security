package secrets

import "github.com/Ratnadeepdeyroy/docker-security/internal/engine"

// Register adds the secrets module to the registry. The master agent calls this
// from modules.Default() during integration; this package never edits the
// shared registry file.
func Register(r *engine.Registry) { r.Register(New()) }
