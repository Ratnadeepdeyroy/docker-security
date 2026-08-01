package vuln

import "github.com/Ratnadeepdeyroy/docker-security/internal/engine"

// Register adds the vuln module to the registry. The master agent calls this
// from modules.Default() during integration; this package never edits the
// shared registry file itself (SHARED_CONTRACT §2).
func Register(r *engine.Registry) { r.Register(New()) }
