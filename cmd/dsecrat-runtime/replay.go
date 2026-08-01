package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	rt "github.com/Ratnadeepdeyroy/docker-security/internal/runtime"
)

// cmdReplay runs the sensor over a recorded telemetry stream — the working
// offline detection path. It builds a Daemon from the flags and streams each
// detection to the chosen sink as it fires, then prints a summary. This is the
// same engine a live node would run; only the event source differs.
func cmdReplay(args []string) int {
	// Go's flag package stops at the first positional, so accept the scenario
	// path either before the flags (the natural `replay scenario.json --flag`)
	// or after them (`replay --flag scenario.json`).
	var scenarioPath string
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		scenarioPath, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	format := fs.String("format", "text", "output format: text|json")
	mode := fs.String("mode", "detect", "response posture: detect|enforce")
	ack := fs.Bool("i-acknowledge", false, "arm destructive response in enforce mode")
	forensicsDir := fs.String("forensics-dir", "", "write a tamper-evident forensic bundle per detection")
	incidents := fs.Bool("incidents", false, "attach a structured incident + containment playbook per detection")
	enableAgent := fs.Bool("enable-agent", false, "enable the AI-agent-runtime rule (DS-RAT-RT-100)")
	enableAnomaly := fs.Bool("enable-anomaly", false, "enable baseline anomaly detection (needs --baseline)")
	baselinePath := fs.String("baseline", "", "learned baseline JSON for anomaly detection")
	egressAllow := fs.String("egress-allow", "", "known-good egress allowlist (comma-separated domains/IPs/CIDRs)")
	learnProfile := fs.Bool("learn-profile", false, "learn behavior and emit a least-privilege seccomp profile")
	profileOut := fs.String("profile-out", "", "directory for generated seccomp profiles (default: stdout)")
	webhook := fs.String("webhook", "", "POST each detection as JSON to this URL")
	alertFile := fs.String("alert-file", "", "append each detection as a JSON line to this file")
	useSyslog := fs.Bool("syslog", false, "also send detections to the local syslog daemon")
	exceptions := fs.String("exceptions", "", "JSON file of rule exceptions to suppress vetted-benign detections")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if scenarioPath == "" {
		if fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "replay: expected exactly one <scenario.json> argument")
			return 2
		}
		scenarioPath = fs.Arg(0)
	} else if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "replay: unexpected extra arguments after flags")
		return 2
	}
	scenario, err := loadScenarioFile(scenarioPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay: %v\n", err)
		return 2
	}

	opts, err := optionsFromFlags(*enableAgent, *enableAnomaly, *baselinePath, *egressAllow)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay: %v\n", err)
		return 2
	}

	var exceptionSet *rt.ExceptionSet
	if *exceptions != "" {
		exceptionSet, err = rt.LoadExceptions(*exceptions)
		if err != nil {
			fmt.Fprintf(os.Stderr, "replay: %v\n", err)
			return 2
		}
	}

	ctx, cancel := signalContext()
	defer cancel()

	if *learnProfile {
		return runLearnProfile(ctx, scenario, opts, *profileOut)
	}

	policy, code := policyFromFlags(*mode, *ack)
	if code != 0 {
		return code
	}

	sink, flush, closeSinks, err := newSink(*format, *webhook, *alertFile, *useSyslog)
	if err != nil {
		fmt.Fprintf(os.Stderr, "replay: %v\n", err)
		return 2
	}
	cfg := rt.DaemonConfig{
		Options:       opts,
		Images:        scenario.Images,
		Policy:        policy,
		ForensicsDir:  *forensicsDir,
		EmitIncidents: *incidents,
		Sink:          sink,
		Exceptions:    exceptionSet,
	}
	if policy.Mode == rt.ResponseEnforce && policy.Acknowledged {
		cfg.Responder = rt.NewEnforcingResponder(policy)
	}
	res, err := cfg.Run(ctx, rt.NewReplaySource(scenario.Events))
	if err != nil {
		closeSinks()
		fmt.Fprintf(os.Stderr, "replay: %v\n", err)
		return 1
	}
	flush(res)
	if err := closeSinks(); err != nil {
		fmt.Fprintf(os.Stderr, "replay: %v\n", err)
	}
	if len(res.Records) > 0 {
		return 1
	}
	return 0
}

// --- options / policy from flags -----------------------------------------

func optionsFromFlags(agent, anomaly bool, baselinePath, egress string) (rt.Options, error) {
	opts := rt.Options{EnableAgentRuntime: agent, EnableAnomaly: anomaly}
	if egress != "" {
		for _, p := range strings.Split(egress, ",") {
			if p = strings.TrimSpace(p); p != "" {
				opts.EgressAllow = append(opts.EgressAllow, p)
			}
		}
	}
	if anomaly {
		if baselinePath == "" {
			return opts, fmt.Errorf("--enable-anomaly requires --baseline")
		}
		b, err := loadBaselineFile(baselinePath)
		if err != nil {
			return opts, err
		}
		opts.Baseline = b
	}
	return opts, nil
}

func policyFromFlags(mode string, ack bool) (rt.ResponsePolicy, int) {
	switch mode {
	case "", "detect":
		return rt.DefaultResponsePolicy(), 0
	case "enforce":
		if !ack {
			fmt.Fprintf(os.Stderr, "replay: enforce mode requires --i-acknowledge\n  (%q)\n", rt.EnforceAck)
			return rt.ResponsePolicy{}, 3
		}
		// Kill/quarantine only High+ detections by default, so arming enforce
		// cannot destroy a workload over an Info/Low/Medium finding. KillSeverity 0
		// (Unknown) would put every detection above the threshold — a footgun.
		return rt.ResponsePolicy{Mode: rt.ResponseEnforce, Acknowledged: true, KillSeverity: engine.SeverityHigh}, 0
	default:
		fmt.Fprintf(os.Stderr, "replay: unknown --mode %q (want detect|enforce)\n", mode)
		return rt.ResponsePolicy{}, 2
	}
}

// --- profile learning -----------------------------------------------------

// runLearnProfile replays telemetry in learning mode, then emits a
// least-privilege seccomp profile per observed workload. Detection still runs,
// but the point here is the generated prevention artifact handed to Phase 7.
func runLearnProfile(ctx context.Context, sc *rt.Scenario, opts rt.Options, outDir string) int {
	opts.EnableAnomaly = true // learning mode: accumulate a baseline as we observe
	opts.Baseline = nil
	det := rt.NewDetector(opts, sc.Images)
	if _, err := det.Run(ctx, rt.NewReplaySource(sc.Events)); err != nil {
		fmt.Fprintf(os.Stderr, "learn-profile: %v\n", err)
		return 1
	}
	baseline := det.Baseline()
	if baseline == nil || len(baseline.Workloads) == 0 {
		fmt.Fprintln(os.Stderr, "learn-profile: no workloads observed in telemetry")
		return 1
	}
	keys := make([]string, 0, len(baseline.Workloads))
	for k := range baseline.Workloads {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic output order

	for _, key := range keys {
		prof := rt.GenerateSeccompProfile(baseline, key)
		data, _ := json.MarshalIndent(prof, "", "  ")
		if outDir == "" {
			fmt.Printf("# seccomp profile for %s\n%s\n", prof.Meta.Image, data)
			continue
		}
		if err := os.MkdirAll(outDir, 0o750); err != nil {
			fmt.Fprintf(os.Stderr, "learn-profile: %v\n", err)
			return 1
		}
		name := "seccomp-" + sanitize(prof.Meta.Image) + ".json"
		path := filepath.Join(outDir, name)
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "learn-profile: %v\n", err)
			return 1
		}
		fmt.Printf("wrote %s (%d allowed syscalls)\n", path, len(prof.Syscalls[0].Names))
	}
	return 0
}

// sanitize turns an image reference into a safe filename fragment.
func sanitize(s string) string {
	if s == "" {
		return "workload"
	}
	r := strings.NewReplacer("/", "_", ":", "_", "@", "_")
	return r.Replace(s)
}
