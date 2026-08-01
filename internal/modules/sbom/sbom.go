// Package sbom is the engine module wrapper around internal/sbom. It projects a
// full Software Bill of Materials into the unified Finding model: an INFO
// summary of what was inventoried, plus INFO findings for any non-fatal
// cataloger warnings. The rich SBOM itself is retrieved via the `dsecrat sbom`
// command (or internal/sbom.Generate) rather than the Finding stream.
package sbom

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	sbomlib "github.com/Ratnadeepdeyroy/docker-security/internal/sbom"
)

const moduleName = "sbom"

// Module is the SBOM-generation capability (CAPABILITY_SPEC domain 1).
type Module struct{}

// New returns an SBOM module.
func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "Software Bill of Materials: enumerate OS + language packages (domain 1)"
}
func (m *Module) Domains() []string { return []string{"1"} }

func (m *Module) Supports(t engine.TargetType) bool {
	return t == engine.TargetImage || t == engine.TargetFilesystem
}

// Analyze builds the SBOM and returns summary findings.
func (m *Module) Analyze(ctx context.Context, t *engine.Target) ([]engine.Finding, error) {
	doc, err := sbomlib.Generate(ctx, t)
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	findings = append(findings, engine.Finding{
		RuleID:      "DS-RAT-SBOM-001",
		Module:      moduleName,
		Severity:    engine.SeverityInfo,
		Title:       fmt.Sprintf("SBOM: %d components inventoried", len(doc.Components)),
		Description: summarize(doc),
		Resource:    doc.Source.Name,
		References:  []string{"https://www.cisa.gov/sbom"},
		Metadata: map[string]string{
			"components": fmt.Sprintf("%d", len(doc.Components)),
			"distro":     doc.Source.Distro,
		},
	})

	for _, w := range doc.Warnings {
		findings = append(findings, engine.Finding{
			RuleID:      "DS-RAT-SBOM-002",
			Module:      moduleName,
			Severity:    engine.SeverityInfo,
			Title:       "SBOM cataloger incomplete",
			Description: w,
			Resource:    doc.Source.Name,
		})
	}
	return findings, nil
}

// summarize renders a human breakdown of the SBOM by component type and by the
// cataloger (ecosystem) that produced each component.
func summarize(doc *sbomlib.SBOM) string {
	byType := map[sbomlib.ComponentType]int{}
	byEco := map[string]int{}
	for _, c := range doc.Components {
		byType[c.Type]++
		if c.FoundBy != "" {
			byEco[c.FoundBy]++
		}
	}
	var b strings.Builder
	if doc.Source.Distro != "" {
		fmt.Fprintf(&b, "distro %s; ", doc.Source.Distro)
	}
	fmt.Fprintf(&b, "%d OS, %d libraries, %d applications",
		byType[sbomlib.TypeOS], byType[sbomlib.TypeLibrary], byType[sbomlib.TypeApp])
	if len(byEco) > 0 {
		ecos := make([]string, 0, len(byEco))
		for e, n := range byEco {
			ecos = append(ecos, fmt.Sprintf("%s=%d", e, n))
		}
		sort.Strings(ecos)
		fmt.Fprintf(&b, " (%s)", strings.Join(ecos, ", "))
	}
	return b.String()
}
