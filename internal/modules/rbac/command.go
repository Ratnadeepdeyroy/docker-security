package rbac

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	rbaclib "github.com/Ratnadeepdeyroy/docker-security/internal/rbac"
)

// This file provides the `dsecrat rbac` subcommand body as an exported function.
// Per SHARED_CONTRACT §2 the module never edits cli.go; the master wires this in
// with a one-liner (recorded in NOTES.md). Command is intentionally
// self-contained: parse flags, analyze a path, render text or JSON, and answer
// the occasional "who can X" reverse query.

// Command runs `dsecrat rbac <path> [flags]`. It returns a process exit code:
// 0 success, 2 usage error, 1 analysis error.
func Command(args []string) int {
	fs := flag.NewFlagSet("rbac", flag.ContinueOnError)
	format := fs.String("format", "text", "output format: text|json")
	nhi := fs.Bool("nhi", false, "enable the non-human-identity (NHI) risk graph (AI-age feature, off by default)")
	nowUnix := fs.Int64("now-unix", 0, "reference time (unix seconds) for NHI dormancy; 0 uses a fixed epoch for determinism")
	who := fs.String("who-can", "", "reverse query \"verb:resource[:namespace]\" — list subjects that can do it")
	failOn := fs.String("fail-on", "", "exit non-zero if a finding at or above this severity is present (e.g. HIGH)")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: dsecrat rbac <path-to-rbac-json-or-dir> [--format text|json] [--nhi] [--who-can verb:resource[:ns]] [--fail-on SEV]")
		return 2
	}

	opts := rbaclib.Options{EnableNHI: *nhi}
	if *nowUnix > 0 {
		opts.Now = time.Unix(*nowUnix, 0).UTC()
	}
	report, err := rbaclib.AnalyzePath(fs.Arg(0), opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "rbac: %v\n", err)
		return 1
	}

	if *who != "" {
		return runWhoCan(report, *who, *format)
	}

	switch *format {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report.Risks); err != nil {
			fmt.Fprintf(os.Stderr, "rbac: encode: %v\n", err)
			return 1
		}
	default:
		fmt.Fprint(os.Stdout, report.Text())
	}

	if *failOn != "" {
		if threshold := engine.ParseSeverity(*failOn); threshold != engine.SeverityUnknown && report.Highest() >= threshold {
			return 1
		}
	}
	return 0
}

// runWhoCan answers a reverse "who can verb:resource[:namespace]" query. The
// resource may be "group/resource" to disambiguate apiGroups (e.g. "apps/deployments").
func runWhoCan(report *rbaclib.Report, spec, format string) int {
	verb, apiGroup, resource, namespace, ok := parseWhoCan(spec)
	if !ok {
		fmt.Fprintln(os.Stderr, "rbac: --who-can expects verb:resource[:namespace] (resource may be group/resource)")
		return 2
	}
	subjects := report.WhoCan(verb, apiGroup, resource, namespace)
	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(subjects)
		return 0
	}
	fmt.Fprintf(os.Stdout, "subjects that can %q %q (group %q) in namespace %q: %d\n", verb, resource, apiGroup, namespace, len(subjects))
	for _, s := range subjects {
		fmt.Fprintf(os.Stdout, "  - %s\n", subjectString(s))
	}
	return 0
}

// parseWhoCan splits "verb:resource[:namespace]" and an optional "group/resource".
func parseWhoCan(spec string) (verb, apiGroup, resource, namespace string, ok bool) {
	parts := strings.Split(spec, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return "", "", "", "", false
	}
	verb = parts[0]
	res := parts[1]
	if len(parts) == 3 {
		namespace = parts[2]
	}
	if i := strings.Index(res, "/"); i >= 0 {
		apiGroup, resource = res[:i], res[i+1:]
	} else {
		resource = res
	}
	return verb, apiGroup, resource, namespace, verb != "" && resource != ""
}

// subjectString renders a subject for human output without leaking the internal
// key format.
func subjectString(s rbaclib.Subject) string {
	if s.Kind == "ServiceAccount" {
		return fmt.Sprintf("ServiceAccount %s/%s", s.Namespace, s.Name)
	}
	return fmt.Sprintf("%s %s", s.Kind, s.Name)
}
