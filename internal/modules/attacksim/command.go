package attacksim

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	simlib "github.com/Ratnadeepdeyroy/docker-security/internal/attacksim"
)

// This file provides the `dsecrat validate` subcommand body as an exported function
// (the master wires it into cli.go — see NOTES.md). It runs the safe
// adversary-emulation harness and prints which controls hold and where the gaps
// are. Running requires an explicit acknowledgement flag; without it the command
// refuses, mirroring the module's off-by-default posture.

// Command runs `dsecrat validate [flags]`. Exit codes: 0 no gaps, 1 gaps found,
// 2 usage error, 3 refused (missing acknowledgement).
func Command(args []string) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	ack := fs.Bool("i-acknowledge", false, "acknowledge that this runs SIMULATED, non-destructive attack scenarios (required)")
	controlsDir := fs.String("controls-dir", "", "directory of recorded control JSON files; empty uses the built-in reference controls")
	baseline := fs.String("baseline", "", "baseline JSON file; when set, report detections that regressed (went silent)")
	format := fs.String("format", "text", "output format: text|json")
	only := fs.String("only", "", "comma-separated scenario IDs to run (default: all)")
	writeBaseline := fs.String("write-baseline", "", "write the current run as a baseline to this path and exit")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !*ack {
		fmt.Fprintf(os.Stderr, "dsecrat validate refused: pass --i-acknowledge to run simulated attack scenarios.\n(%q)\n", simlib.AckPhrase())
		return 3
	}

	controls, err := buildControls(*controlsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "validate: %v\n", err)
		return 1
	}
	opts := simlib.Options{Authorized: true, Acknowledgement: simlib.AckPhrase()}
	if *only != "" {
		opts.Only = strings.Split(*only, ",")
	}
	rep, err := simlib.Run(context.Background(), simlib.Builtin(), controls, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "validate: %v\n", err)
		return 1
	}

	if *writeBaseline != "" {
		data, _ := json.MarshalIndent(simlib.BaselineFrom(rep), "", "  ")
		if err := os.WriteFile(*writeBaseline, append(data, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "validate: write baseline: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stdout, "wrote baseline for %d scenarios to %s\n", rep.Total, *writeBaseline)
		return 0
	}

	var regressions []simlib.Regression
	if *baseline != "" {
		if data, rerr := os.ReadFile(*baseline); rerr == nil {
			if b, berr := simlib.LoadBaseline(data); berr == nil {
				regressions = simlib.CompareBaseline(rep, b)
			}
		}
	}

	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(struct {
			Report      *simlib.Report      `json:"report"`
			Regressions []simlib.Regression `json:"regressions,omitempty"`
		}{rep, regressions})
	} else {
		printText(rep, regressions)
	}

	if rep.Gaps > 0 || len(regressions) > 0 {
		return 1
	}
	return 0
}

// buildControls returns recorded controls from a directory, or the reference set.
func buildControls(dir string) (*simlib.ControlSet, error) {
	if dir == "" {
		return simlib.NewControlSet(simlib.ReferenceAdmissionControl(), simlib.ReferenceDetectionControl()), nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read controls dir: %w", err)
	}
	set := simlib.NewControlSet()
	n := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, rerr := os.ReadFile(dir + string(os.PathSeparator) + e.Name())
		if rerr != nil {
			return nil, rerr
		}
		ctrl, perr := simlib.LoadFixtureControl(data)
		if perr != nil {
			return nil, perr
		}
		set.Add(ctrl)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("no recorded controls in %q", dir)
	}
	return set, nil
}

// printText renders a human summary of the validation run.
func printText(rep *simlib.Report, regressions []simlib.Regression) {
	fmt.Fprintf(os.Stdout, "Attack-sim control validation: %d scenarios, %d validated, %d gap(s)\n\n", rep.Total, rep.Validated, rep.Gaps)
	for _, r := range rep.Results {
		status := "OK  "
		if r.Gap {
			status = "GAP "
		}
		fmt.Fprintf(os.Stdout, "  [%s] %s %s (%s / %s) expect=%s\n", status, r.Scenario.ID, r.Scenario.Name, r.Scenario.Technique, r.Scenario.TacticName, r.Scenario.Expect)
	}
	if len(regressions) > 0 {
		fmt.Fprintf(os.Stdout, "\nRegressions (controls that went silent vs baseline):\n")
		for _, reg := range regressions {
			fmt.Fprintf(os.Stdout, "  ! %s %s (%s)\n", reg.ScenarioID, reg.Name, reg.Technique)
		}
	}
}
