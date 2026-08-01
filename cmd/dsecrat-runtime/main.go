// Command dsecrat-runtime is the runtime threat-detection daemon for the
// docker-security project. It is a separate binary from the main `dsecrat` scanner
// because it plays a different role: a node-resident sensor (DaemonSet-capable)
// that observes process/file/network/syscall telemetry and detects malicious
// behavior mapped to MITRE ATT&CK for Containers.
//
// Today it ships with a fully working OFFLINE replay mode — feed it a recorded
// telemetry stream and it runs the exact deterministic detection engine a live
// node would, with response, forensics, incidents, and least-privilege profile
// generation. `run` attempts live capture by polling /proc, which is Linux-only;
// on other platforms (and anywhere /proc-based capture is unsupported) it fails
// cleanly and points you at replay mode instead.
//
// Subcommands:
//
//	replay <scenario.json>   detect over a recorded telemetry stream (offline)
//	run                      watch the host live via /proc (Linux only)
//	rules                    list the detection rule set and ATT&CK mapping
//	version                  print sensor and rule-set versions
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	rt "github.com/Ratnadeepdeyroy/docker-security/internal/runtime"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run dispatches a subcommand and returns a process exit code. Keeping it a
// function (not main) makes the dispatch testable.
func run(args []string) int {
	if len(args) == 0 {
		usage()
		return 2
	}
	switch args[0] {
	case "replay":
		return cmdReplay(args[1:])
	case "run":
		return cmdRunLive(args[1:])
	case "rules":
		return cmdRules(args[1:])
	case "version":
		fmt.Printf("dsecrat-runtime %s (ruleset %s)\n", rt.SensorVersion, rt.RuleSetVersion)
		return 0
	case "-h", "--help", "help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "dsecrat-runtime: unknown command %q\n\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `dsecrat-runtime — container runtime threat detection sensor

usage:
  dsecrat-runtime replay <scenario.json> [flags]   detect over recorded telemetry (offline)
  dsecrat-runtime run [flags]                       watch the host live via /proc (Linux only;
                                                     unsupported/parked on other platforms)
  dsecrat-runtime rules [--format text|json]        list detection rules + ATT&CK mapping
  dsecrat-runtime version                           print versions

run flags (Linux only; requires /proc and the container runtime socket mounted
into the process, e.g. -v /proc:/host/proc and the docker/containerd socket
for a DaemonSet deployment):
  --format text|json     output format (default text)
  --mode detect|enforce  response posture (default detect; enforce needs --i-acknowledge)
  --i-acknowledge        arm destructive response in enforce mode
  --webhook URL          POST each detection as JSON to URL
  --alert-file PATH      append each detection as a JSON line to PATH
  --syslog               also send detections to the local syslog daemon
  --forensics-dir DIR    write a tamper-evident forensic bundle per detection
  --enable-agent         enable the AI-agent-runtime rule (DS-RAT-RT-100, off by default)
  --enable-anomaly       enable baseline anomaly detection (needs --baseline)
  --baseline FILE        learned baseline JSON for anomaly detection
  --egress-allow CSV     known-good egress allowlist (domains/IPs/CIDRs)

replay flags:
  --format text|json     output format (default text)
  --mode detect|enforce  response posture (default detect; enforce needs --i-acknowledge)
  --i-acknowledge        arm destructive response in enforce mode
  --forensics-dir DIR    write a tamper-evident forensic bundle per detection
  --incidents            attach a structured incident + containment playbook per detection
  --enable-agent         enable the AI-agent-runtime rule (DS-RAT-RT-100, off by default)
  --enable-anomaly       enable baseline anomaly detection (needs --baseline)
  --baseline FILE        learned baseline JSON for anomaly detection
  --egress-allow CSV     known-good egress allowlist (domains/IPs/CIDRs)
  --learn-profile        learn behavior and emit a least-privilege seccomp profile
  --profile-out DIR      directory for generated seccomp profiles (default stdout)
  --webhook URL          POST each detection as JSON to URL
  --alert-file PATH      append each detection as a JSON line to PATH
  --syslog               also send detections to the local syslog daemon
  --exceptions FILE      JSON file of rule exceptions to suppress vetted-benign detections

exit codes: 0 no detections · 1 detections found · 2 usage · 3 live capture unavailable
`)
}

// signalContext returns a context cancelled on SIGINT/SIGTERM so a run (a live
// sensor especially) shuts down gracefully instead of being hard-killed.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// cmdRunLive watches the host live via /proc on Linux, running the same
// detection engine as replay mode but fed by a polling ProcSource instead of
// a recorded scenario. On platforms without /proc-based capture support (e.g.
// darwin) it fails cleanly with guidance to use replay mode, rather than
// pretending to attach to telemetry it cannot observe.
// hasKernelBTF reports whether the kernel exposes BTF type information at the
// canonical path — the prerequisite for the CO-RE eBPF sensor. When absent, the
// daemon falls back to the /proc source.
func hasKernelBTF() bool {
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	return err == nil
}

func cmdRunLive(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	format := fs.String("format", "text", "output format: text|json")
	webhook := fs.String("webhook", "", "POST each detection as JSON to this URL")
	alertFile := fs.String("alert-file", "", "append each detection as a JSON line to this file")
	useSyslog := fs.Bool("syslog", false, "also send detections to the local syslog daemon")
	forensicsDir := fs.String("forensics-dir", "", "write a tamper-evident forensic bundle per detection")
	enableAgent := fs.Bool("enable-agent", false, "enable the AI-agent-runtime rule (DS-RAT-RT-100)")
	enableAnomaly := fs.Bool("enable-anomaly", false, "enable baseline anomaly detection (needs --baseline)")
	baselinePath := fs.String("baseline", "", "learned baseline JSON for anomaly detection")
	egressAllow := fs.String("egress-allow", "", "known-good egress allowlist (comma-separated domains/IPs/CIDRs)")
	mode := fs.String("mode", "detect", "response posture: detect|enforce")
	ack := fs.Bool("i-acknowledge", false, "arm destructive response in enforce mode")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	policy, code := policyFromFlags(*mode, *ack)
	if code != 0 {
		return code
	}

	// TODO(follow-up): support a configurable --proc-root (for DaemonSet
	// deployments that bind-mount the host /proc at /host/proc) once
	// NewProcSource grows an option for it; ProcSource's root is not
	// currently settable from this package.
	// Prefer the eBPF sensor when the kernel exposes BTF (CO-RE-capable): it
	// captures every execve in-kernel with no sampling gap. Fall back to the
	// /proc-polling source when eBPF is unavailable (no BTF, missing caps, or
	// the loader errors), and to a clean exit-3 when neither works (e.g. off
	// Linux).
	resolver := rt.NewContainerResolver()
	var src rt.EventSource
	var err error
	sensor := "ebpf"
	if hasKernelBTF() {
		src, err = rt.NewEBPFSource(rt.LiveConfig{}, resolver)
	} else {
		err = rt.ErrLiveUnsupported // skip straight to the /proc fallback
	}
	if err != nil {
		if sensor == "ebpf" {
			fmt.Fprintf(os.Stderr, "dsecrat-runtime: eBPF sensor unavailable (%v); falling back to /proc\n", err)
		}
		sensor = "proc"
		src, err = rt.NewProcSource(rt.LiveConfig{}, resolver)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "dsecrat-runtime run: %v\n", err)
		fmt.Fprintln(os.Stderr, "hint: capture telemetry elsewhere and analyze it offline with `dsecrat-runtime replay <scenario.json>`.")
		return 3
	}
	fmt.Fprintf(os.Stderr, "dsecrat-runtime: live sensor=%s\n", sensor)

	// In armed enforce mode, turn on in-kernel enforcement if the source
	// supports it (only the eBPF sensor does): a shell execing inside a
	// container is SIGKILL'd by the probe before it runs.
	if policy.Mode == rt.ResponseEnforce && policy.Acknowledged {
		if enf, ok := src.(rt.ShellKillEnforcer); ok {
			if err := enf.ArmShellKill(); err != nil {
				fmt.Fprintf(os.Stderr, "dsecrat-runtime: %v\n", err)
			} else {
				fmt.Fprintln(os.Stderr, "dsecrat-runtime: in-kernel shell-kill enforcement ARMED")
			}
		}
	}

	opts, err := optionsFromFlags(*enableAgent, *enableAnomaly, *baselinePath, *egressAllow)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dsecrat-runtime run: %v\n", err)
		return 2
	}

	sink, flush, closeSinks, err := newSink(*format, *webhook, *alertFile, *useSyslog)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dsecrat-runtime run: %v\n", err)
		return 2
	}

	cfg := rt.DaemonConfig{
		Options:      opts,
		Policy:       policy,
		ForensicsDir: *forensicsDir,
		Sink:         sink,
	}
	if policy.Mode == rt.ResponseEnforce && policy.Acknowledged {
		cfg.Responder = rt.NewEnforcingResponder(policy)
	}

	ctx, cancel := signalContext()
	defer cancel()

	res, err := cfg.Run(ctx, src)
	if err != nil {
		closeSinks()
		fmt.Fprintf(os.Stderr, "dsecrat-runtime run: %v\n", err)
		return 1
	}
	flush(res)
	if err := closeSinks(); err != nil {
		fmt.Fprintf(os.Stderr, "dsecrat-runtime run: %v\n", err)
	}
	if len(res.Records) > 0 {
		return 1
	}
	return 0
}
