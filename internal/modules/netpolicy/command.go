package netpolicy

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/netmon"
)

// This file provides the `dsecrat net` subcommand body as an exported function.
// Per SHARED_CONTRACT §2 the module never edits cli.go; the master wires this in
// with a one-liner (recorded in NOTES.md). Command is self-contained: parse
// flags, load a recorded capture, and either report detections, generate a
// least-privilege policy, dry-run a candidate policy, or diff against a current
// one.

// Command runs `dsecrat net <capture.json> [flags]`. Exit codes: 0 ok, 1 error or
// --fail-on threshold met, 2 usage error.
func Command(args []string) int {
	fs := flag.NewFlagSet("net", flag.ContinueOnError)
	format := fs.String("format", "text", "output format: text|json")
	gen := fs.String("gen", "", "generate policy from the baseline: policy|fqdn|deny")
	workload := fs.String("workload", "", "restrict --gen/--diff to this workload id (default: all)")
	namespace := fs.String("namespace", "", "Kubernetes namespace for generated policy")
	dryRun := fs.String("dry-run", "", "audit the capture against a candidate allowlist JSON file")
	diff := fs.String("diff", "", "diff a current allowlist JSON file against the generated one (needs --workload)")
	intent := fs.Bool("intent", false, "enable egress intent modelling (AI-age feature, off by default)")
	agentEgress := fs.Bool("agent-egress", false, "enable AI-agent egress governance (AI-age feature, off by default)")
	nowUnix := fs.Int64("now-unix", 0, "reference time (unix seconds) for windowed detection; 0 derives it from the capture")
	failOn := fs.String("fail-on", "", "exit non-zero if an anomaly at or above this severity is present (e.g. HIGH)")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: dsecrat net <capture.json> [--gen policy|fqdn|deny] [--workload id] [--namespace ns] [--dry-run allowlist.json] [--diff current.json] [--intent] [--agent-egress] [--now-unix N] [--fail-on SEV] [--format text|json]")
		return 2
	}

	capture, err := netmon.LoadCapture(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "net: %v\n", err)
		return 1
	}

	opts := netmon.Options{EnableIntent: *intent, EnableAgentEgress: *agentEgress}
	if *nowUnix > 0 {
		opts.Now = time.Unix(*nowUnix, 0).UTC()
	}
	genOpts := GenOptions{Namespace: *namespace, UseIntent: *intent, Opts: opts}

	switch {
	case *gen != "":
		return runGenerate(capture, *gen, *workload, genOpts, *format)
	case *dryRun != "":
		return runDryRun(capture, *dryRun, *format)
	case *diff != "":
		return runDiff(capture, *diff, *workload, genOpts, *format)
	default:
		return runReport(capture, opts, *format, *failOn)
	}
}

// runReport prints the detection report and applies --fail-on gating.
func runReport(c *netmon.Capture, opts netmon.Options, format, failOn string) int {
	report := netmon.Analyze(c, opts)
	if format == "json" {
		if err := encodeJSON(report.Anomalies); err != nil {
			fmt.Fprintf(os.Stderr, "net: %v\n", err)
			return 1
		}
	} else {
		printReportText(c, report)
	}
	if failOn != "" {
		if threshold := engine.ParseSeverity(failOn); threshold != engine.SeverityUnknown && report.Highest() >= threshold {
			return 1
		}
	}
	return 0
}

func printReportText(c *netmon.Capture, r *netmon.Report) {
	fmt.Printf("network capture: %d workload(s), %d flow(s), policy_mode=%s\n", len(c.Workloads), len(c.Flows), policyModeOrNone(c.PolicyMode))
	if len(r.Anomalies) == 0 {
		fmt.Println("no anomalies detected")
		return
	}
	fmt.Printf("%d anomaly(ies):\n", len(r.Anomalies))
	for _, a := range r.Anomalies {
		dst := ""
		if a.Dest != "" {
			dst = " → " + a.Dest
		}
		fmt.Printf("  [%s] %s (%s) workload=%s%s\n", a.Severity, a.Title, a.Kind, a.Workload, dst)
		fmt.Printf("        %s\n", a.Detail)
	}
}

// runGenerate emits a generated policy for one or all workloads.
func runGenerate(c *netmon.Capture, kind, workload string, g GenOptions, format string) int {
	gens := GenerateForCapture(c, g)
	if workload != "" {
		gens = filterWorkload(gens, workload)
		if len(gens) == 0 {
			fmt.Fprintf(os.Stderr, "net: no egress observed for workload %q\n", workload)
			return 1
		}
	}
	if len(gens) == 0 {
		fmt.Fprintln(os.Stderr, "net: no workloads with egress to generate policy for")
		return 1
	}

	if format == "json" {
		return jsonOrErr(gens)
	}

	for i, gp := range gens {
		if i > 0 {
			fmt.Println("---")
		}
		switch kind {
		case "deny":
			fmt.Print(RenderNetworkPolicy(gp.DefaultDeny))
		case "fqdn":
			fmt.Print(RenderFQDNAllowlist(gp))
		case "policy":
			fmt.Print(RenderNetworkPolicy(gp.Policy))
		default:
			fmt.Fprintf(os.Stderr, "net: unknown --gen %q (want policy|fqdn|deny)\n", kind)
			return 2
		}
	}
	return 0
}

// runDryRun audits the capture against a candidate allowlist file.
func runDryRun(c *netmon.Capture, path, format string) int {
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "net: open allowlist: %v\n", err)
		return 1
	}
	defer f.Close()
	allow, err := DecodeAllowlist(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "net: %v\n", err)
		return 1
	}
	res := DryRun(c, allow)
	if format == "json" {
		return jsonOrErr(res)
	}
	fmt.Printf("dry-run: %d destination(s) allowed, %d would be denied\n", res.AllowedDests, res.DeniedDests)
	for _, d := range res.Denied {
		fmt.Printf("  DENY %s → %s:%d (%dx): %s\n", d.Workload, d.Dest, d.Port, d.Count, d.Reason)
	}
	return 0
}

// runDiff diffs a current allowlist against the generated one for a workload.
func runDiff(c *netmon.Capture, path, workload string, g GenOptions, format string) int {
	if workload == "" {
		fmt.Fprintln(os.Stderr, "net: --diff requires --workload")
		return 2
	}
	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "net: open current allowlist: %v\n", err)
		return 1
	}
	defer f.Close()
	current, err := DecodeAllowlist(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "net: %v\n", err)
		return 1
	}
	gens := filterWorkload(GenerateForCapture(c, g), workload)
	if len(gens) == 0 {
		fmt.Fprintf(os.Stderr, "net: no egress observed for workload %q\n", workload)
		return 1
	}
	generated := AllowlistFromPolicy(gens[0])
	d := DiffAllowlists(current, generated)
	d.Workload = workload
	if format == "json" {
		return jsonOrErr(d)
	}
	fmt.Print(d.Render())
	return 0
}

func filterWorkload(gens []GeneratedPolicy, id string) []GeneratedPolicy {
	var out []GeneratedPolicy
	for _, gp := range gens {
		if gp.Workload == id {
			out = append(out, gp)
		}
	}
	return out
}

func encodeJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func jsonOrErr(v any) int {
	if err := encodeJSON(v); err != nil {
		fmt.Fprintf(os.Stderr, "net: encode: %v\n", err)
		return 1
	}
	return 0
}
