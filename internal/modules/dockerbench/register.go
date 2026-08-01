package dockerbench

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/compliance"
	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// Register adds this module to the registry. The master agent calls this from
// modules.Default() during integration; this package never edits the shared
// registry file. See NOTES.md for the exact one-line wiring.
func Register(r *engine.Registry) { r.Register(New()) }

// --- target-metadata plumbing ----------------------------------------------

// evidencePath is where the evidence snapshot lives for this target.
func evidencePath(t *engine.Target) string { return t.Location }

// optNarrative reports whether the caller opted into the (off-by-default)
// continuous-compliance narrative via target metadata.
func optNarrative(t *engine.Target) bool {
	return t.Metadata != nil && t.Metadata["compliance.narrative"] == "true"
}

// narrativeClock returns the injected timestamp used to keep narrative output
// deterministic in the analysis path. Absent metadata yields the zero time —
// analysis never reads the wall clock.
func narrativeClock(t *engine.Target) time.Time {
	if t.Metadata != nil {
		if s := t.Metadata["compliance.now"]; s != "" {
			if ts, err := time.Parse(time.RFC3339, s); err == nil {
				return ts
			}
		}
	}
	return time.Time{}
}

func itoa(n int) string { return strconv.Itoa(n) }

// --- `dsecrat bench docker` command -------------------------------------------

// RunCommand implements `dsecrat bench docker [flags] <evidence-path>`. It is the
// exported command body the master wires into cli.go (see NOTES.md); this
// package owns the logic, the frontend owns the dispatch. Unlike Analyze, the
// command is a frontend and may read the wall clock.
func RunCommand(args []string) int {
	fs := flag.NewFlagSet("bench docker", flag.ContinueOnError)
	format := fs.String("format", "table", "output format: table|json")
	level := fs.Int("level", 2, "max CIS profile level to assess: 1 or 2")
	narrative := fs.Bool("narrative", false, "emit the continuous-compliance narrative (off by default)")
	baseline := fs.String("baseline", "", "path to a prior report JSON for drift reporting")
	waiversPath := fs.String("waivers", "", "path to a waivers JSON file")
	failOn := fs.String("fail-on", "", "exit non-zero on: fail|warn")
	out := fs.String("out", "", "write output to this file (default stdout)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: dsecrat bench docker [flags] <evidence.json|dir>\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "bench docker: missing <evidence path>")
		fs.Usage()
		return 2
	}

	ev, err := Load(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "bench docker:", err)
		return 1
	}
	for _, n := range ev.Notes {
		fmt.Fprintln(os.Stderr, "bench docker: note:", n)
	}

	b := Benchmark()
	b.Controls = filterByLevel(b.Controls, *level)
	rep := b.Run(checksFor(ev))

	now := time.Now().UTC()
	var waivers *compliance.Waivers
	if *waiversPath != "" {
		w, err := loadWaivers(*waiversPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bench docker:", err)
			return 1
		}
		waivers = w
		waivers.Apply(rep, b.Code, now)
	}

	w := io.Writer(os.Stdout)
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bench docker:", err)
			return 1
		}
		defer f.Close()
		w = f
	}

	if err := renderReport(w, *format, rep, *baseline, *narrative, waivers, now); err != nil {
		fmt.Fprintln(os.Stderr, "bench docker:", err)
		return 1
	}

	if failGate(rep, *failOn) {
		return 1
	}
	return 0
}

// filterByLevel drops controls above the requested profile level.
func filterByLevel(controls []compliance.Control, maxLevel int) []compliance.Control {
	if maxLevel >= 2 {
		return controls
	}
	out := controls[:0:0]
	for _, c := range controls {
		if c.Level != compliance.Level2 {
			out = append(out, c)
		}
	}
	return out
}

// loadWaivers reads a waivers JSON file (an array of compliance.Waiver).
func loadWaivers(path string) (*compliance.Waivers, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read waivers %q: %w", path, err)
	}
	var items []compliance.Waiver
	if err := json.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("parse waivers %q: %w", path, err)
	}
	return compliance.NewWaivers(items), nil
}

// renderReport writes the report in the requested format, optionally with a
// drift section (against a baseline) and the narrative.
func renderReport(w io.Writer, format string, rep *compliance.Report, baselinePath string, narrative bool, waivers *compliance.Waivers, now time.Time) error {
	var baseline *compliance.Report
	if baselinePath != "" {
		b, err := loadReport(baselinePath)
		if err != nil {
			return err
		}
		baseline = b
	}

	switch format {
	case "json":
		payload := map[string]any{"report": rep}
		if baseline != nil {
			payload["drift"] = compliance.Diff(baseline, rep)
		}
		if narrative {
			payload["narrative"] = compliance.BuildNarrative(rep, compliance.NarrativeOptions{
				Now: now, Baseline: baseline, Waivers: waivers,
			})
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	default:
		return renderTable(w, rep, baseline, narrative, waivers, now)
	}
}

// loadReport reads a previously exported compliance.Report JSON.
func loadReport(path string) (*compliance.Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read report %q: %w", path, err)
	}
	var rep compliance.Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse report %q: %w", path, err)
	}
	return &rep, nil
}

// renderTable prints a control-by-control table plus a summary line.
func renderTable(w io.Writer, rep *compliance.Report, baseline *compliance.Report, narrative bool, waivers *compliance.Waivers, now time.Time) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "%s v%s (profile %s)\n", rep.Benchmark, rep.Version, orDefault(rep.Profile, "default"))
	fmt.Fprintln(tw, "STATUS\tCONTROL\tLEVEL\tTITLE")
	for _, r := range rep.Results {
		status := r.Status.String()
		if r.Waived {
			status = "WAIVED"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", status, r.Control.ID, r.Control.Level, r.Control.Title)
	}
	counts := rep.Counts()
	fmt.Fprintf(tw, "\nScore %d%%  —  %d pass, %d fail, %d warn, %d info\n",
		rep.Score(), counts[compliance.StatusPass], counts[compliance.StatusFail],
		counts[compliance.StatusWarn], counts[compliance.StatusInfo])
	if err := tw.Flush(); err != nil {
		return err
	}
	if baseline != nil {
		d := compliance.Diff(baseline, rep)
		fmt.Fprintf(w, "\nDrift since baseline: %d regressed, %d fixed (score %d%%->%d%%)\n",
			len(d.Regressed), len(d.Fixed), d.ScoreFrom, d.ScoreTo)
	}
	if narrative {
		n := compliance.BuildNarrative(rep, compliance.NarrativeOptions{Now: now, Baseline: baseline, Waivers: waivers})
		fmt.Fprintln(w, "\n--- Compliance narrative ---")
		fmt.Fprint(w, n.Text())
	}
	return nil
}

// failGate reports whether the report should exit non-zero for CI gating.
func failGate(rep *compliance.Report, failOn string) bool {
	switch failOn {
	case "fail":
		return rep.FailsAt(false)
	case "warn":
		return rep.FailsAt(true)
	default:
		return false
	}
}

// ensure the module satisfies the engine contract at compile time.
var _ engine.Module = (*Module)(nil)
