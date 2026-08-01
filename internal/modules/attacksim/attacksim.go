// Package attacksim is the engine module wrapper around internal/attacksim. It
// runs the safe adversary-emulation harness and projects control GAPS (scenarios
// where no admission/detection control fired) into the Finding model, so a scan
// can answer "are our Phase 4/5 defenses actually working?". It is OFF BY
// DEFAULT and safe by construction: Analyze returns nothing unless the caller
// sets an explicit authorization acknowledgement in the target metadata, and the
// harness only evaluates inert scenario descriptors — it never executes anything.
package attacksim

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	simlib "github.com/Ratnadeepdeyroy/docker-security/internal/attacksim"
	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

const moduleName = "attacksim"

// Target metadata keys. All are opt-in; without the authorization key the module
// is completely inert (returns no findings, no error).
const (
	// metaAuthorize must equal simlib.AckPhrase() for the harness to run. This is
	// the explicit, conscious opt-in that keeps adversary emulation off by default.
	metaAuthorize = "attacksim.authorize"
	// metaControlsDir points at a directory of recorded control JSON files (the
	// stub for a not-yet-built Phase 4/5). Absent → the reference controls are
	// used, which validate every built-in scenario.
	metaControlsDir = "attacksim.controls_dir"
	// metaBaseline points at a baseline JSON file; when set, the run also reports
	// regressions (controls that used to fire and now do not).
	metaBaseline = "attacksim.baseline"
)

// Module is the attack-simulation / control-validation capability
// (CAPABILITY_SPEC domain 14, pentest/validation).
type Module struct{}

// New returns an attack-sim module.
func New() *Module { return &Module{} }

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "Safe, opt-in adversary emulation: validate that admission/detection controls fire (domain 14)"
}
func (m *Module) Domains() []string { return []string{"14"} }

// Supports handles filesystem targets (the carrier for control fixtures/baseline),
// but the module only does anything when explicitly authorized via metadata.
func (m *Module) Supports(t engine.TargetType) bool {
	return t == engine.TargetFilesystem || t == engine.TargetContainer
}

// Analyze runs the harness ONLY when authorized. Absent the acknowledgement it
// returns nothing, so it is silent in ordinary scans. When authorized it emits a
// gating-neutral coverage summary plus one finding per control gap (and per
// regression when a baseline is supplied).
func (m *Module) Analyze(ctx context.Context, t *engine.Target) ([]engine.Finding, error) {
	if t.Metadata[metaAuthorize] != simlib.AckPhrase() {
		// Off by default. Not an error — simply not opted in.
		return nil, nil
	}
	controls, err := loadControls(t)
	if err != nil {
		return nil, err
	}
	rep, err := simlib.Run(ctx, simlib.Builtin(), controls, simlib.Options{
		Authorized:      true,
		Acknowledgement: simlib.AckPhrase(),
	})
	if err != nil {
		return nil, fmt.Errorf("attacksim run: %w", err)
	}

	findings := make([]engine.Finding, 0, rep.Gaps+1)
	findings = append(findings, engine.Finding{
		RuleID:      "DS-RAT-ATK-000",
		Module:      moduleName,
		Severity:    engine.SeverityInfo,
		Title:       fmt.Sprintf("Control validation: %d/%d scenarios caught, %d gap(s)", rep.Validated, rep.Total, rep.Gaps),
		Description: "Safe, simulated ATT&CK-for-Containers scenarios evaluated against the configured controls. No actions were executed.",
		Resource:    t.Location,
		References:  []string{"https://attack.mitre.org/matrices/enterprise/containers/"},
		Metadata: map[string]string{
			"validated": fmt.Sprintf("%d", rep.Validated),
			"gaps":      fmt.Sprintf("%d", rep.Gaps),
			"total":     fmt.Sprintf("%d", rep.Total),
		},
	})
	for _, res := range rep.Results {
		if res.Gap {
			findings = append(findings, gapFinding(res))
		}
	}
	findings = append(findings, regressionFindings(t, rep)...)
	return findings, nil
}

// --- Projection ----------------------------------------------------------

// gapFinding turns an uncaught scenario into a Finding at the scenario's declared
// severity — a control that should have fired did not.
func gapFinding(res simlib.ScenarioResult) engine.Finding {
	sc := res.Scenario
	var evaluated []string
	for _, v := range res.Verdicts {
		evaluated = append(evaluated, v.Control)
	}
	seen := "no control of kind " + string(sc.Expect) + " was configured"
	if len(evaluated) > 0 {
		seen = "evaluated by: " + strings.Join(evaluated, ", ")
	}
	return engine.Finding{
		RuleID:      sc.ID,
		Module:      moduleName,
		Severity:    engine.ParseSeverity(sc.Severity),
		Title:       fmt.Sprintf("Undetected: %s (%s)", sc.Name, sc.Technique),
		Description: fmt.Sprintf("%s No %s control fired for ATT&CK %s (%s); %s.", sc.Description, sc.Expect, sc.Technique, sc.TacticName, seen),
		Resource:    sc.Event.Target,
		Remediation: fmt.Sprintf("Add or fix a %s control for %s (%s). This is a defensive gap, not an active compromise.", sc.Expect, sc.Technique, sc.Name),
		References:  sc.References,
		Metadata: map[string]string{
			"technique": sc.Technique,
			"tactic":    sc.TacticName,
			"expect":    string(sc.Expect),
			"action":    sc.Event.Action,
		},
	}
}

// regressionFindings compares the current run to a baseline (when metadata points
// at one) and emits a finding for each control that went silent — the AI-age
// continuous-validation signal. Absent a baseline it returns nothing.
func regressionFindings(t *engine.Target, rep *simlib.Report) []engine.Finding {
	path := t.Metadata[metaBaseline]
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil // a missing baseline must not fail the run
	}
	baseline, err := simlib.LoadBaseline(data)
	if err != nil {
		return nil
	}
	var out []engine.Finding
	for _, reg := range simlib.CompareBaseline(rep, baseline) {
		out = append(out, engine.Finding{
			RuleID:      reg.ScenarioID,
			Module:      moduleName,
			Severity:    engine.SeverityHigh,
			Title:       fmt.Sprintf("Detection regression: %s (%s) went silent", reg.Name, reg.Technique),
			Description: "A control that fired in the recorded baseline no longer fires. A detection that stops detecting is an incident, not a passing test.",
			Resource:    reg.ScenarioID,
			Remediation: "Investigate why the control stopped firing (rule disabled, agent down, policy drift) before shipping.",
			Metadata:    map[string]string{"technique": reg.Technique, "regression": "true"},
		})
	}
	return out
}

// --- Control loading -----------------------------------------------------

// loadControls builds the control set: recorded controls from the metadata
// directory when supplied (the Phase 4/5 stub), otherwise the built-in reference
// controls that validate every scenario.
func loadControls(t *engine.Target) (*simlib.ControlSet, error) {
	dir := t.Metadata[metaControlsDir]
	if dir == "" {
		return simlib.NewControlSet(simlib.ReferenceAdmissionControl(), simlib.ReferenceDetectionControl()), nil
	}
	set := simlib.NewControlSet()
	loaded := 0
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			return fmt.Errorf("read control %q: %w", p, readErr)
		}
		ctrl, parseErr := simlib.LoadFixtureControl(data)
		if parseErr != nil {
			return fmt.Errorf("load control %q: %w", p, parseErr)
		}
		set.Add(ctrl)
		loaded++
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("load controls from %q: %w", dir, err)
	}
	if loaded == 0 {
		return nil, fmt.Errorf("no recorded controls found in %q", dir)
	}
	return set, nil
}
