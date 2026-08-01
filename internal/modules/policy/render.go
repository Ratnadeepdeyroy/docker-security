package policy

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/Ratnadeepdeyroy/docker-security/internal/policy"
)

// --- Command output rendering ----------------------------------------------

// renderEval writes an evaluation result as a table or JSON. The JSON form is
// the machine contract (a CI step or an agent parses it); the table is for a
// human reading pipeline logs.
func renderEval(w io.Writer, format string, res *policy.Result, ex *policy.Explanation) error {
	if format == "json" {
		payload := map[string]any{"result": res}
		if ex != nil {
			payload["explanation"] = ex
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	}

	fmt.Fprintf(w, "Policy: %s (mode %s)\n", res.Policy, res.Mode)
	fmt.Fprintf(w, "Decision: %s\n", up(string(res.Decision)))

	if denials := res.Denials(); len(denials) > 0 {
		fmt.Fprintln(w, "\nDenials:")
		writeRules(w, denials)
	}
	if warnings := res.Warnings(); len(warnings) > 0 {
		fmt.Fprintln(w, "\nWarnings:")
		writeRules(w, warnings)
	}
	if waived := res.WaivedRules(); len(waived) > 0 {
		fmt.Fprintln(w, "\nWaived:")
		for _, rr := range waived {
			fmt.Fprintf(w, "  - %s (%s)\n", rr.RuleID, rr.WaiverReason)
		}
	}

	if ex != nil && len(ex.Remediation) > 0 {
		fmt.Fprintln(w, "\nTo be admitted:")
		for _, r := range ex.Remediation {
			fmt.Fprintf(w, "  - %s\n", r)
		}
	}
	return nil
}

// writeRules prints a severity-tagged, aligned list of rule outcomes.
func writeRules(w io.Writer, rules []policy.RuleResult) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, rr := range rules {
		msg := rr.Message
		if rr.Error != "" {
			msg = "evaluation error (fail-closed): " + rr.Error
		}
		fmt.Fprintf(tw, "  [%s]\t%s\t%s\n", rr.Severity, rr.RuleID, msg)
	}
	tw.Flush()
}

// renderSuite writes a policy test-suite run.
func renderSuite(w io.Writer, format string, sr policy.SuiteResult) error {
	if format == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(sr)
	}
	for _, r := range sr.Results {
		status := "PASS"
		if !r.Pass {
			status = "FAIL"
		}
		fmt.Fprintf(w, "%s  %s\n", status, r.Name)
		if !r.Pass {
			fmt.Fprintf(w, "      %s\n", r.Detail)
		}
	}
	fmt.Fprintf(w, "\n%d passed, %d failed\n", sr.Passed, sr.Failed)
	return nil
}
