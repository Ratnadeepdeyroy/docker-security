// Package cli is the command-line frontend. It is a thin adapter: it builds a
// Target from arguments, runs the shared engine, and renders the report with a
// formatter. All analysis logic lives in modules, not here.
package cli

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/admission"
	"github.com/Ratnadeepdeyroy/docker-security/internal/authz"
	"github.com/Ratnadeepdeyroy/docker-security/internal/compliance"
	"github.com/Ratnadeepdeyroy/docker-security/internal/connector"
	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/mcp"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/attacksim"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/harden"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/netpolicy"
	policymod "github.com/Ratnadeepdeyroy/docker-security/internal/modules/policy"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/rbac"
	secretsmod "github.com/Ratnadeepdeyroy/docker-security/internal/modules/secrets"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/verify"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/vuln"
	"github.com/Ratnadeepdeyroy/docker-security/internal/plugin"
	"github.com/Ratnadeepdeyroy/docker-security/internal/report"
	sbomlib "github.com/Ratnadeepdeyroy/docker-security/internal/sbom"
	"github.com/Ratnadeepdeyroy/docker-security/internal/server"
	"github.com/Ratnadeepdeyroy/docker-security/internal/watch"
)

// Version is the tool version. All 15 CAPABILITY_SPEC domains have a capability
// module; the live-eBPF capture paths remain the one approved-dependency
// follow-up (see README).
const Version = "0.1.0"

// Main dispatches a subcommand and returns a process exit code.
func Main(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "scan":
		return cmdScan(rest)
	case "watch":
		return cmdWatch(rest)
	case "sbom":
		return cmdSBOM(rest)
	case "serve":
		return cmdServe(rest)
	case "modules":
		return cmdModules(rest)
	// Capability subcommands: each module owns its own specialized frontend
	// (the generic engine still runs every module via `scan`).
	case "vuln":
		return vuln.Command(rest)
	case "secrets":
		return secretsmod.Command(rest)
	case "policy":
		return policymod.Command(rest)
	case "admission":
		return admission.Command(rest)
	case "authz":
		return authz.Command(rest)
	case "harden":
		return harden.Command(rest)
	case "net":
		return netpolicy.Command(rest)
	case "rbac":
		return rbac.Command(rest)
	case "attacksim":
		return attacksim.Command(rest)
	case "mcp":
		return mcp.Command(modules.Default(), rest)
	case "plugins":
		return plugin.Command(rest)
	case "compliance":
		return cmdCompliance(rest)
	case "sign":
		return verify.SignCommand(rest)
	case "attest":
		return verify.AttestCommand(rest)
	case "verify":
		return verify.VerifyCommand(rest)
	case "version", "-v", "--version":
		fmt.Printf("docker-security %s\n", Version)
		return 0
	case "help", "-h", "--help":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage(os.Stderr)
		return 2
	}
}

func usage(w *os.File) {
	fmt.Fprintf(w, `docker-security %s — unified container-security tool

Usage:
  dsecrat scan [flags] <target>   Analyze a Dockerfile / image / path (runs all modules)
  dsecrat watch [flags] <target>  Continuously re-scan on an interval; emit only new findings
  dsecrat sbom [flags] <target>   Generate an SBOM for an image tar / OCI layout / path
  dsecrat serve [flags]           Start the HTTP API + web dashboard (--store for inventory)
  dsecrat modules                 List available capability modules

Capability commands (specialized frontends; "scan" runs every module):
  dsecrat vuln ...                Vulnerability scan / advisory DB management
  dsecrat secrets ...             Secret detection / honeytoken generation
  dsecrat policy eval|test ...    Policy-as-code CI gate
  dsecrat admission serve ...     Kubernetes admission webhook
  dsecrat authz serve ...         Docker daemon authorization plugin (standalone-Docker gate)
  dsecrat harden verify|gen-profile ...   seccomp/AppArmor profiles & hardening checks
  dsecrat net ...                 Network egress analysis & policy generation
  dsecrat rbac ...                Identity/RBAC risk analysis
  dsecrat attacksim ...           Safe adversary emulation
  dsecrat mcp ...                 Model Context Protocol server (agent-native interface)
  dsecrat plugins ...             Manage out-of-process capability plugins
  dsecrat compliance scan|report|coverage|packs   Framework compliance (CIS/NIST/PCI/ISO/SSDF) with evidence
  dsecrat sign|attest|verify ...  Sign images, attach attestations, verify signatures (domain 9)
  dsecrat-runtime replay|run ...  Runtime threat detection daemon (separate binary)
  dsecrat version                 Print version

Run "dsecrat scan -h" or "dsecrat sbom -h" for flags.
`, Version)
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	format := fs.String("format", "table", "output format: table|json|sarif")
	modsCSV := fs.String("modules", "", "comma-separated module names (default: all)")
	typ := fs.String("type", "", "target type override: dockerfile|image|filesystem")
	failOn := fs.String("fail-on", "", "exit non-zero if a finding at/above this severity exists: critical|high|medium|low|info")
	webhook := fs.String("webhook", "", "POST the JSON report to this URL")
	slack := fs.String("slack", "", "post a summary to this Slack incoming-webhook URL")
	sarifOut := fs.String("sarif-out", "", "write a SARIF report to this file path")
	siem := fs.String("siem", "", "POST findings as newline-delimited JSON events to this SIEM/HEC URL")
	mcpPush := fs.String("mcp-push", "", "push the report to this MCP ingestion endpoint")
	vulnDB := fs.String("vuln-db", "", "advisory DB path (default: $DSECRAT_VULN_DB, then ~/.dsecrat/vulndb.json, then embedded)")
	vulnNow := fs.String("vuln-now", "", "pin the clock (RFC3339, e.g. 2026-01-01T00:00:00Z) used for vuln DB staleness and DS-RAT-VULN-EOL checks, for deterministic CI runs")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: dsecrat scan [flags] <target>\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "scan: missing <target>")
		fs.Usage()
		return 2
	}
	ref := fs.Arg(0)

	tt := engine.TargetType(*typ)
	if tt == "" {
		tt = engine.DetectType(ref)
	}

	target, err := buildTarget(tt, ref)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan:", err)
		return 1
	}
	if p := resolveVulnDB(*vulnDB); p != "" {
		target.Metadata["vuln.db"] = p
	}
	if *vulnNow != "" {
		ts, err := time.Parse(time.RFC3339, *vulnNow)
		if err != nil {
			fmt.Fprintln(os.Stderr, "scan: --vuln-now:", err)
			return 2
		}
		target.Metadata["vuln.now"] = ts.UTC().Format(time.RFC3339)
	}

	formatter, err := report.Get(*format)
	if err != nil {
		fmt.Fprintln(os.Stderr, "scan:", err)
		return 2
	}

	eng := engine.New(modules.Default())
	rep := eng.Run(context.Background(), target, splitCSV(*modsCSV)...)

	if err := formatter.Format(os.Stdout, rep); err != nil {
		fmt.Fprintln(os.Stderr, "scan:", err)
		return 1
	}

	if conns := buildConnectors(*webhook, *slack, *sarifOut, *siem, *mcpPush); len(conns) > 0 {
		for _, err := range connector.Dispatch(context.Background(), rep, conns...) {
			fmt.Fprintln(os.Stderr, "warning: connector", err)
		}
	}

	if rep.FailsAt(engine.ParseSeverity(*failOn)) {
		return 1
	}
	return 0
}

// cmdWatch runs continuous monitoring: it re-scans the target on an interval,
// diffs each run against the previous, and dispatches only newly-appeared
// findings to any configured connectors — turning the one-shot `scan` into the
// spec's "continuous re-scan / drift" control with no new detection logic.
func cmdWatch(args []string) int {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	interval := fs.Duration("interval", 5*time.Minute, "re-scan interval (e.g. 30s, 5m, 1h)")
	modsCSV := fs.String("modules", "", "comma-separated module names (default: all)")
	typ := fs.String("type", "", "target type override: dockerfile|image|filesystem")
	count := fs.Int("count", 0, "stop after this many cycles (0 = run until interrupted)")
	webhook := fs.String("webhook", "", "POST newly-appeared findings to this URL")
	slack := fs.String("slack", "", "post new-finding summaries to this Slack incoming-webhook URL")
	sarifOut := fs.String("sarif-out", "", "write each delta as SARIF to this file path (overwritten per cycle)")
	siem := fs.String("siem", "", "POST new findings as newline-delimited JSON to this SIEM/HEC URL")
	mcpPush := fs.String("mcp-push", "", "push each delta to this MCP ingestion endpoint")
	vulnDB := fs.String("vuln-db", "", "advisory DB path (default: $DSECRAT_VULN_DB, then ~/.dsecrat/vulndb.json, then embedded)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: dsecrat watch [flags] <target>\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "watch: missing <target>")
		fs.Usage()
		return 2
	}
	if *interval <= 0 {
		fmt.Fprintln(os.Stderr, "watch: --interval must be positive")
		return 2
	}
	ref := fs.Arg(0)

	tt := engine.TargetType(*typ)
	if tt == "" {
		tt = engine.DetectType(ref)
	}
	target, err := buildTarget(tt, ref)
	if err != nil {
		fmt.Fprintln(os.Stderr, "watch:", err)
		return 1
	}
	if p := resolveVulnDB(*vulnDB); p != "" {
		target.Metadata["vuln.db"] = p
	}

	w := &watch.Watcher{
		Scanner: watch.EngineScanner{
			Engine:  engine.New(modules.Default()),
			Target:  target,
			Modules: splitCSV(*modsCSV),
		},
		Connectors: buildConnectors(*webhook, *slack, *sarifOut, *siem, *mcpPush),
		OnlyDeltas: true,
		Observer: watch.ObserverFunc(func(rep *engine.Report, d watch.Delta) {
			ts := rep.GeneratedAt.Format(time.RFC3339)
			if d.Changed() {
				fmt.Fprintf(os.Stderr, "[%s] %d finding(s) total; +%d new, -%d cleared\n",
					ts, len(rep.Findings), len(d.New), len(d.Cleared))
				for _, f := range d.New {
					fmt.Fprintf(os.Stderr, "  + %-8s %s %s\n", f.Severity, f.RuleID, f.Title)
				}
			} else {
				fmt.Fprintf(os.Stderr, "[%s] %d finding(s) total; no change\n", ts, len(rep.Findings))
			}
		}),
	}

	ctx, cancel := signalContext()
	defer cancel()

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	fmt.Fprintf(os.Stderr, "watching %s every %s (ctrl-c to stop)\n", ref, *interval)

	if *count > 0 {
		// Bounded run: first cycle immediate, then count-1 ticks.
		w.Run(ctx)
		for i := 1; i < *count; i++ {
			select {
			case <-ctx.Done():
				return 0
			case <-ticker.C:
				w.Run(ctx)
			}
		}
		return 0
	}
	w.Loop(ctx, ticker.C)
	return 0
}

// signalContext returns a context cancelled on SIGINT/SIGTERM so `watch` exits
// cleanly on ctrl-c.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// buildConnectors assembles the outbound connectors requested via flags. The
// richer integrations that need structured config (Jira, GitHub code scanning)
// are available as connector constructors for programmatic/API use rather than
// single-value CLI flags.
func buildConnectors(webhook, slack, sarifOut, siem, mcpPush string) []connector.Connector {
	var conns []connector.Connector
	if webhook != "" {
		conns = append(conns, connector.NewWebhook(webhook))
	}
	if slack != "" {
		conns = append(conns, connector.NewSlack(slack))
	}
	if sarifOut != "" {
		conns = append(conns, connector.NewSARIFFile(sarifOut))
	}
	if siem != "" {
		conns = append(conns, connector.NewSIEM(siem))
	}
	if mcpPush != "" {
		conns = append(conns, connector.NewMCPPush(mcpPush))
	}
	return conns
}

func buildTarget(tt engine.TargetType, ref string) (*engine.Target, error) {
	if tt == engine.TargetDockerfile {
		return engine.NewDockerfileTarget(ref)
	}
	return &engine.Target{Type: tt, Location: ref, Metadata: map[string]string{}}, nil
}

// resolveVulnDB picks the advisory DB for this run. Precedence: explicit
// --vuln-db flag, then DSECRAT_VULN_DB, then ~/.dsecrat/vulndb.json when present,
// else "" (the embedded snapshot).
func resolveVulnDB(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv("DSECRAT_VULN_DB"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	p := filepath.Join(home, ".dsecrat", "vulndb.json")
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// cmdCompliance implements the data-driven compliance layer:
// it runs the engine over a target, maps findings onto versioned control packs
// via the crosswalk, and reports coverage / evidence across frameworks.
func cmdCompliance(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: dsecrat compliance <scan|report|coverage|packs> [flags] [target]")
		return 2
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "packs":
		return compliancePacks(rest)
	case "scan", "report", "coverage":
		return complianceScan(sub, rest)
	default:
		fmt.Fprintf(os.Stderr, "compliance: unknown subcommand %q (want scan|report|coverage|packs)\n", sub)
		return 2
	}
}

// loadCatalog loads the embedded packs, or packs from a directory when set.
func loadCatalog(packsDir string) (*compliance.Catalog, error) {
	if packsDir != "" {
		return compliance.LoadPacksFromDir(packsDir)
	}
	return compliance.LoadEmbeddedPacks()
}

func compliancePacks(args []string) int {
	fs := flag.NewFlagSet("compliance packs", flag.ContinueOnError)
	packsDir := fs.String("packs", "", "load control packs from this directory (default: embedded)")
	checkUpdates := fs.Bool("check-updates", false, "report each pack's source URL to reconcile against upstream")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cat, err := loadCatalog(*packsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "compliance:", err)
		return 1
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "FRAMEWORK\tVERSION\tCONTROLS\tSOURCE")
	for _, fw := range cat.Frameworks() {
		p := cat.Pack(fw)
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", p.Framework, p.Version, len(p.Controls), p.SourceURL)
	}
	tw.Flush()
	if *checkUpdates {
		fmt.Fprintln(os.Stderr, "\ncheck-updates: compare each VERSION above against its SOURCE (offline build does not fetch);")
		fmt.Fprintln(os.Stderr, "a newer upstream version should open a pack reconciliation task before release.")
	}
	return 0
}

func complianceScan(mode string, args []string) int {
	fs := flag.NewFlagSet("compliance "+mode, flag.ContinueOnError)
	fwCSV := fs.String("framework", "", "comma-separated frameworks (default: all loaded packs)")
	packsDir := fs.String("packs", "", "load control packs from this directory (default: embedded)")
	attest := fs.String("attest", "", "path to a waiver/attestation register (JSON)")
	format := fs.String("format", "json", "report format: json|csv|oscal|md (report mode)")
	out := fs.String("out", "", "write the report to this file (default: stdout)")
	typ := fs.String("type", "", "target type override: image|filesystem|dockerfile")
	failOn := fs.Bool("fail-on-gap", false, "exit non-zero if any control is Failed")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "compliance %s: missing <target>\n", mode)
		return 2
	}
	ref := fs.Arg(0)

	tt := engine.TargetType(*typ)
	if tt == "" {
		tt = engine.DetectType(ref)
	}
	target, err := buildTarget(tt, ref)
	if err != nil {
		fmt.Fprintln(os.Stderr, "compliance:", err)
		return 1
	}
	cat, err := loadCatalog(*packsDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "compliance:", err)
		return 1
	}
	reg, err := compliance.LoadRegister(*attest)
	if err != nil {
		fmt.Fprintln(os.Stderr, "compliance:", err)
		return 1
	}
	frameworks := splitCSV(*fwCSV)
	if len(frameworks) == 0 {
		frameworks = cat.Frameworks()
	}

	eng := engine.New(modules.Default())
	rep := eng.Run(context.Background(), target)
	creport := compliance.RunPacks(cat, frameworks, rep, compliance.RunOptions{
		Now: time.Now().UTC(), ToolVersion: Version, Target: target.Location, Register: reg,
	})

	switch mode {
	case "report":
		data, err := compliance.Render(creport, compliance.ExportFormat(*format))
		if err != nil {
			fmt.Fprintln(os.Stderr, "compliance:", err)
			return 2
		}
		if *out != "" {
			if err := os.WriteFile(*out, data, 0o644); err != nil {
				fmt.Fprintln(os.Stderr, "compliance:", err)
				return 1
			}
			fmt.Fprintf(os.Stderr, "compliance: wrote %s report (%d controls) to %s\n", *format, len(creport.Results), *out)
		} else {
			os.Stdout.Write(data)
		}
	default: // scan | coverage
		printComplianceSummary(creport, mode == "scan")
	}

	if *failOn {
		for _, r := range creport.Results {
			if r.Disposition == compliance.DispFailed {
				return 1
			}
		}
	}
	return 0
}

// printComplianceSummary renders the per-framework coverage table and, in scan
// mode, the outstanding gaps.
func printComplianceSummary(rep *compliance.ComplianceReport, withGaps bool) {
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(os.Stdout, "compliance: %s (%d frameworks, %d controls)\n\n", rep.Target, len(rep.Frameworks), len(rep.Results))
	fmt.Fprintln(tw, "FRAMEWORK\tCOVERAGE\tSATISFIED\tFAILED\tWAIVED\tN/A\tMANUAL\tTOTAL")
	for _, s := range compliance.Coverage(rep) {
		fmt.Fprintf(tw, "%s\t%.1f%%\t%d\t%d\t%d\t%d\t%d\t%d\n",
			s.Framework, s.CoveragePct, s.Satisfied, s.Failed, s.Waived, s.NotApplicable, s.Manual, s.Total)
	}
	tw.Flush()
	if withGaps {
		gaps := compliance.Gaps(rep)
		if len(gaps) == 0 {
			fmt.Fprintln(os.Stdout, "\nno gaps: every control resolved.")
			return
		}
		fmt.Fprintf(os.Stdout, "\ngaps (%d):\n", len(gaps))
		for _, g := range gaps {
			fmt.Fprintf(os.Stdout, "  [%s] %s %s — %s\n", g.Disposition, g.Framework, g.ID, g.Title)
		}
	}
}

func cmdSBOM(args []string) int {
	fs := flag.NewFlagSet("sbom", flag.ContinueOnError)
	format := fs.String("format", "cyclonedx", "SBOM format: cyclonedx|spdx")
	out := fs.String("out", "", "write the SBOM to this file (default: stdout)")
	typ := fs.String("type", "", "target type override: image|filesystem")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: dsecrat sbom [flags] <image.tar|oci-layout-dir|path>\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "sbom: missing <target>")
		fs.Usage()
		return 2
	}
	ref := fs.Arg(0)

	tt := engine.TargetType(*typ)
	if tt == "" {
		tt = detectSBOMTarget(ref)
	}
	if tt != engine.TargetImage && tt != engine.TargetFilesystem {
		fmt.Fprintf(os.Stderr, "sbom: unsupported target type %q (want image or filesystem)\n", tt)
		return 2
	}

	target := &engine.Target{Type: tt, Location: ref, Metadata: map[string]string{}}
	doc, err := sbomlib.Generate(context.Background(), target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sbom:", err)
		return 1
	}
	for _, w := range doc.Warnings {
		fmt.Fprintln(os.Stderr, "sbom: warning:", w)
	}

	meta := sbomlib.DocMeta{
		Timestamp:   time.Now().UTC(),
		Serial:      sbomSerial(doc),
		ToolName:    "docker-security",
		ToolVersion: Version,
	}
	data, err := sbomlib.Marshal(doc, sbomlib.Format(*format), meta)
	if err != nil {
		fmt.Fprintln(os.Stderr, "sbom:", err)
		return 2
	}

	if *out == "" {
		os.Stdout.Write(data)
		return 0
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "sbom:", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "sbom: wrote %s (%d components) to %s\n", *format, len(doc.Components), *out)
	return 0
}

// detectSBOMTarget classifies an SBOM target: a regular file is an image
// archive; a directory holding an OCI layout is an image; any other directory
// is a filesystem to scan; a non-existent path is assumed to be an image ref.
func detectSBOMTarget(ref string) engine.TargetType {
	info, err := os.Stat(ref)
	if err != nil {
		return engine.TargetImage
	}
	if !info.IsDir() {
		return engine.TargetImage
	}
	for _, marker := range []string{"oci-layout", "index.json"} {
		if _, err := os.Stat(filepath.Join(ref, marker)); err == nil {
			return engine.TargetImage
		}
	}
	return engine.TargetFilesystem
}

// sbomSerial derives a stable urn:uuid serial number from the source identity,
// so re-running against the same image yields the same document identifier.
func sbomSerial(doc *sbomlib.SBOM) string {
	seed := doc.Source.Name + "|" + doc.Source.ImageDigest
	return "urn:uuid:" + sbomlib.DeterministicUUID(seed)
}

func cmdModules(_ []string) int {
	reg := modules.Default()
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tDOMAINS\tDESCRIPTION")
	for _, m := range reg.All() {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", m.Name(), strings.Join(m.Domains(), ","), m.Description())
	}
	tw.Flush()
	return 0
}

func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	addr := fs.String("addr", ":8080", "listen address")
	storeDir := fs.String("store", "", "persist scan results in this directory and expose the inventory API")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	srv := server.New(modules.Default())
	if *storeDir != "" {
		if err := srv.MountStore(*storeDir); err != nil {
			fmt.Fprintln(os.Stderr, "serve:", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "inventory store: %s\n", *storeDir)
	}
	fmt.Fprintf(os.Stderr, "docker-security %s serving on %s\n", Version, *addr)
	if err := http.ListenAndServe(*addr, srv); err != nil {
		fmt.Fprintln(os.Stderr, "serve:", err)
		return 1
	}
	return 0
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
