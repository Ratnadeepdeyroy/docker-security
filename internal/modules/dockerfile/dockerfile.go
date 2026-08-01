package dockerfile

import (
	"context"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

const moduleName = "dockerfile"

// Module is the Dockerfile static-analysis capability.
type Module struct{}

// New returns a Dockerfile module.
func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "Static analysis & linting of Dockerfiles (best-practice + CIS build controls)"
}
func (m *Module) Domains() []string { return []string{"3"} }

func (m *Module) Supports(t engine.TargetType) bool { return t == engine.TargetDockerfile }

// Analyze parses the Dockerfile and runs every rule against it.
func (m *Module) Analyze(_ context.Context, t *engine.Target) ([]engine.Finding, error) {
	df := Parse(string(t.Content))
	var findings []engine.Finding
	for _, r := range rules {
		findings = append(findings, r(df, t.Location)...)
	}
	return findings, nil
}
