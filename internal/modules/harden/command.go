package harden

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	hardenlib "github.com/Ratnadeepdeyroy/docker-security/internal/harden"
)

// --- `dsecrat harden` command body ----------------------------------------------
//
// The frontend owns argument dispatch; this exported entry point is the command
// body the master wires into cli.go (see NOTES.md). As a frontend it may read the
// wall clock (for exception expiry), unlike Analyze. Two subcommands:
//
//	dsecrat harden verify <spec.json> [--format table|json] [--trust LEVEL]
//	                    [--fail-on SEV] [--bundle] [--observation obs.json] [--now RFC3339]
//	dsecrat harden gen-profile --from <obs.json> --type seccomp|apparmor
//	                    [--mode enforce|audit] [--name NAME] [--arch a,b] [--out PATH]

// Command implements `dsecrat harden <subcommand>`, returning a process exit code
// (0 ok, 2 usage error, 1 runtime error).
func Command(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "harden: expected a subcommand (verify|gen-profile)")
		return 2
	}
	switch args[0] {
	case "verify":
		return cmdVerify(args[1:])
	case "gen-profile":
		return cmdGenProfile(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "harden: unknown subcommand %q (want verify|gen-profile)\n", args[0])
		return 2
	}
}

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("harden verify", flag.ContinueOnError)
	format := fs.String("format", "table", "output format: table|json")
	trust := fs.String("trust", "internal", "workload trust level: trusted|internal|untrusted|hostile")
	failOn := fs.String("fail-on", "", "exit non-zero if a finding at or above this severity is present (e.g. HIGH)")
	bundle := fs.Bool("bundle", false, "emit the agent-appliable hardening bundle (off by default)")
	obsPath := fs.String("observation", "", "path to a recorded/declared Observation JSON for profile generation in the bundle")
	nowStr := fs.String("now", "", "reference time (RFC3339) for exception expiry; default is the wall clock")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: dsecrat harden verify [flags] <spec.json>\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "harden verify: missing <spec.json>")
		fs.Usage()
		return 2
	}

	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "harden verify:", err)
		return 1
	}
	workloads, err := hardenlib.Parse(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "harden verify:", err)
		return 1
	}
	if len(workloads) == 0 {
		fmt.Fprintln(os.Stderr, "harden verify: no container/pod/OCI spec recognised in input")
		return 1
	}

	now := time.Now().UTC()
	if *nowStr != "" {
		if ts, perr := time.Parse(time.RFC3339, *nowStr); perr == nil {
			now = ts
		} else {
			fmt.Fprintln(os.Stderr, "harden verify: bad --now:", perr)
			return 2
		}
	}
	trustLevel := hardenlib.ParseTrustLevel(*trust)

	var obs hardenlib.Observation
	if *obsPath != "" {
		if obs, err = loadObservationFile(*obsPath); err != nil {
			fmt.Fprintln(os.Stderr, "harden verify:", err)
			return 1
		}
	}

	// Build a per-workload view.
	type wlView struct {
		Name    string                          `json:"name"`
		Runtime hardenlib.RuntimeRecommendation `json:"runtime"`
		Results []hardenlib.Result              `json:"results"`
		Bundle  *hardenlib.HardeningBundle      `json:"bundle,omitempty"`
	}
	var views []wlView
	worst := engine.SeverityUnknown
	for i := range workloads {
		w := &workloads[i]
		rep := hardenlib.Verify(w)
		for _, f := range rep.Findings(moduleName) {
			if f.Severity > worst {
				worst = f.Severity
			}
		}
		v := wlView{Name: w.Name, Runtime: hardenlib.RecommendRuntime(w, trustLevel), Results: rep.Results}
		if *bundle {
			v.Bundle = hardenlib.BuildBundle(w, rep, hardenlib.BundleOptions{Observation: obs, Now: now, DryRun: true})
		}
		views = append(views, v)
	}

	out := io.Writer(os.Stdout)
	if strings.EqualFold(*format, "json") {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{"workloads": views}); err != nil {
			fmt.Fprintln(os.Stderr, "harden verify:", err)
			return 1
		}
	} else {
		for i := range workloads {
			w := &workloads[i]
			rep := hardenlib.Verify(w)
			renderTable(out, w, rep, views[i].Runtime, views[i].Bundle)
		}
	}

	if *failOn != "" {
		threshold := engine.ParseSeverity(*failOn)
		if threshold != engine.SeverityUnknown && worst >= threshold {
			return 1
		}
	}
	return 0
}

// renderTable prints a human-readable report for one workload.
func renderTable(out io.Writer, w *hardenlib.Workload, rep *hardenlib.Report, rec hardenlib.RuntimeRecommendation, bundle *hardenlib.HardeningBundle) {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "\nWorkload: %s  (source: %s)\n", w.Name, w.Source)
	fmt.Fprintln(tw, "STATUS\tCONTROL\tTITLE")
	for _, r := range rep.Results {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", statusLabel(r.Status), r.Control.ID, r.Control.Title)
	}
	counts := rep.Counts()
	fmt.Fprintf(tw, "\n%d fail, %d warn, %d info, %d pass\n",
		counts[hardenlib.StatusFail], counts[hardenlib.StatusWarn],
		counts[hardenlib.StatusInfo], counts[hardenlib.StatusPass])
	fmt.Fprintf(tw, "Runtime guidance (%s): %s — %s\n", rec.Trust, rec.Recommended, rec.Rationale)
	tw.Flush()
	if bundle != nil {
		fmt.Fprintf(out, "Hardening bundle (dry-run): addresses %s; seccomp %s mode; %d waived.\n",
			strings.Join(bundle.Addressed, ", "), bundle.SeccompMode, len(bundle.Waived))
	}
}

func statusLabel(s hardenlib.Status) string {
	switch s {
	case hardenlib.StatusFail:
		return "FAIL"
	case hardenlib.StatusWarn:
		return "WARN"
	case hardenlib.StatusInfo:
		return "INFO"
	case hardenlib.StatusNA:
		return "N/A"
	default:
		return "PASS"
	}
}

func cmdGenProfile(args []string) int {
	fs := flag.NewFlagSet("harden gen-profile", flag.ContinueOnError)
	from := fs.String("from", "", "path to a recorded/declared Observation JSON (required)")
	kind := fs.String("type", "seccomp", "profile type: seccomp|apparmor")
	mode := fs.String("mode", "enforce", "seccomp default action: enforce|audit")
	name := fs.String("name", "", "profile name (defaults to the observation's workload label)")
	arch := fs.String("arch", "", "comma-separated seccomp architectures (default: amd64+arm64 family)")
	out := fs.String("out", "", "write to this file (default stdout)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: dsecrat harden gen-profile --from <obs.json> --type seccomp|apparmor [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *from == "" {
		fmt.Fprintln(os.Stderr, "harden gen-profile: --from <obs.json> is required")
		return 2
	}
	obs, err := loadObservationFile(*from)
	if err != nil {
		fmt.Fprintln(os.Stderr, "harden gen-profile:", err)
		return 1
	}
	pname := *name
	if pname == "" {
		pname = obs.Workload
	}

	var payload []byte
	switch strings.ToLower(*kind) {
	case "seccomp":
		opts := hardenlib.SeccompOptions{Name: pname, AuditMode: strings.EqualFold(*mode, "audit")}
		if *arch != "" {
			opts.Architectures = splitCSV(*arch)
		}
		p := hardenlib.GenerateSeccomp(obs, opts)
		payload, err = p.JSON()
		if err != nil {
			fmt.Fprintln(os.Stderr, "harden gen-profile:", err)
			return 1
		}
	case "apparmor":
		p := hardenlib.GenerateAppArmor(obs, pname)
		payload = []byte(p.Render())
	default:
		fmt.Fprintf(os.Stderr, "harden gen-profile: unknown --type %q (want seccomp|apparmor)\n", *kind)
		return 2
	}

	if *out == "" {
		os.Stdout.Write(payload)
		return 0
	}
	if err := os.WriteFile(*out, payload, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "harden gen-profile:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "harden gen-profile: wrote %s profile to %s\n", *kind, *out)
	return 0
}

// loadObservationFile reads and parses an Observation JSON file.
func loadObservationFile(path string) (hardenlib.Observation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return hardenlib.Observation{}, fmt.Errorf("read observation %q: %w", path, err)
	}
	var obs hardenlib.Observation
	if err := json.Unmarshal(data, &obs); err != nil {
		return hardenlib.Observation{}, fmt.Errorf("parse observation %q: %w", path, err)
	}
	return obs, nil
}

// splitCSV splits and trims a comma-separated list, dropping empties.
func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
