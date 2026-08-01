package policy

import "github.com/Ratnadeepdeyroy/docker-security/internal/engine"

// Register adds the policy module to the registry. The master agent calls this
// from modules.Default() during integration; this package never edits the
// shared registry file. See NOTES.md for the exact one-line wiring.
func Register(r *engine.Registry) { r.Register(New()) }

// ensure the module satisfies the engine contract at compile time.
var _ engine.Module = (*Module)(nil)
