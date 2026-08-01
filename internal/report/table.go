package report

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// Table renders a compact human-readable summary and finding list.
type Table struct{}

func (Table) Format(w io.Writer, r *engine.Report) error {
	fmt.Fprintf(w, "docker-security scan report\n")
	fmt.Fprintf(w, "target : %s (%s)\n", r.Target, r.TargetType)

	fmt.Fprintf(w, "modules: ")
	for i, mr := range r.ModuleRuns {
		if i > 0 {
			fmt.Fprint(w, ", ")
		}
		fmt.Fprint(w, mr.Module)
		if mr.Error != "" {
			fmt.Fprintf(w, " (error: %s)", mr.Error)
		}
	}
	fmt.Fprintln(w)

	c := r.Counts()
	fmt.Fprintf(w, "summary: %d findings  (critical=%d high=%d medium=%d low=%d info=%d)\n\n",
		len(r.Findings),
		c[engine.SeverityCritical], c[engine.SeverityHigh], c[engine.SeverityMedium],
		c[engine.SeverityLow], c[engine.SeverityInfo])

	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "No findings.")
		return nil
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tRULE\tLOCATION\tTITLE")
	for _, f := range r.Findings {
		loc := f.Resource
		if f.Location != nil && f.Location.StartLine > 0 {
			loc = fmt.Sprintf("%s:%d", f.Location.Path, f.Location.StartLine)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Severity, f.RuleID, loc, f.Title)
	}
	return tw.Flush()
}
