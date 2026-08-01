package imageaudit

import "github.com/Ratnadeepdeyroy/docker-security/internal/engine"

// Register adds the image-audit module to the registry with its default
// (deterministic CIS baseline) configuration. The master agent calls this from
// modules.Default() during integration; per SHARED_CONTRACT §2 this package
// never edits the shared registry file itself.
//
// To enable the off-by-default attack-surface score in a given frontend,
// register a configured instance instead:
//
//	r.Register(imageaudit.New(imageaudit.WithAttackSurfaceScore()))
func Register(r *engine.Registry) { r.Register(New()) }
