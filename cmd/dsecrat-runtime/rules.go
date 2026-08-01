package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	rt "github.com/Ratnadeepdeyroy/docker-security/internal/runtime"
)

// cmdRules enumerates the detection rule set and its ATT&CK mapping without
// running anything — a coverage report for operators and auditors, and a quick
// way to see which rules are on by default versus opt-in.
func cmdRules(args []string) int {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	format := fs.String("format", "text", "output format: text|json")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	// Enumerate every rule (optional ones included, with their default state).
	set := rt.NewRuleSet(rt.Options{})

	type row struct {
		ID        string `json:"id"`
		Severity  string `json:"severity"`
		Technique string `json:"technique"`
		Tactic    string `json:"tactic"`
		Default   bool   `json:"default_on"`
		Title     string `json:"title"`
	}
	var rows []row
	for _, r := range set.Rules() {
		info := r.Info()
		rows = append(rows, row{
			ID:        r.ID(),
			Severity:  info.Severity.String(),
			Technique: info.Technique.ID,
			Tactic:    info.Technique.Tactic,
			Default:   info.Default,
			Title:     info.Title,
		})
	}

	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(struct {
			RuleSet string      `json:"ruleset"`
			Rules   interface{} `json:"rules"`
		}{rt.RuleSetVersion, rows})
		return 0
	}

	fmt.Printf("dsecrat-runtime detection rules (ruleset %s)\n\n", rt.RuleSetVersion)
	fmt.Printf("%-10s %-8s %-10s %-6s %s\n", "RULE", "SEVERITY", "ATT&CK", "ON", "TITLE")
	for _, r := range rows {
		on := "yes"
		if !r.Default {
			on = "opt-in"
		}
		fmt.Printf("%-10s %-8s %-10s %-6s %s\n", r.ID, r.Severity, r.Technique, on, r.Title)
	}
	return 0
}
