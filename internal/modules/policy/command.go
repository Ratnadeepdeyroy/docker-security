package policy

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/policy"
)

// --- `dsecrat policy` command surface -----------------------------------------
//
// These exported command bodies are wired into cli.go by the master (see
// NOTES.md); this package owns the logic, the frontend owns the dispatch.
// Commands are frontends, so unlike Analyze they may read the wall clock — the
// evaluation time is then injected into the pure engine, keeping determinism at
// the core while defaulting to "now" for humans.

// Command dispatches `dsecrat policy <eval|test> ...`.
func Command(args []string) int {
	if len(args) == 0 {
		policyUsage(os.Stderr)
		return 2
	}
	switch args[0] {
	case "eval":
		return EvalCommand(args[1:])
	case "test":
		return TestCommand(args[1:])
	case "-h", "--help", "help":
		policyUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "policy: unknown subcommand %q\n", args[0])
		policyUsage(os.Stderr)
		return 2
	}
}

func policyUsage(w io.Writer) {
	fmt.Fprint(w, `Usage: dsecrat policy <command> [flags]

Commands:
  eval   Evaluate a policy against a scan report (CI gate)
  test   Run a policy test suite (unit-test policies-as-code)

Run "dsecrat policy eval -h" or "dsecrat policy test -h" for flags.
`)
}

// --- dsecrat policy eval -------------------------------------------------------

// EvalCommand implements `dsecrat policy eval`: gate a scan report against a policy.
func EvalCommand(args []string) int {
	fs := flag.NewFlagSet("policy eval", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "path to the policy JSON (required)")
	reportPath := fs.String("report", "", "path to a `dsecrat scan --format json` report to judge")
	format := fs.String("format", "table", "output format: table|json")
	explain := fs.Bool("explain", false, "include an agent-consumable explanation (off by default)")
	failOn := fs.String("fail-on", "deny", "exit non-zero on: deny|warn|never")
	signed := fs.String("signed", "", "override image signed state: true|false (else inferred from report)")
	verified := fs.String("verified", "", "comma-separated verified predicate-type URIs")
	registry := fs.String("registry", "", "image registry host")
	repository := fs.String("repository", "", "image repository")
	tag := fs.String("tag", "", "image tag")
	digest := fs.String("digest", "", "image digest (sha256:...)")
	imageRef := fs.String("image", "", "full image reference")
	nowStr := fs.String("now", "", "evaluation time (RFC3339) for waiver expiry (default: now)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: dsecrat policy eval --policy <file> [--report <file>] [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *policyPath == "" {
		fmt.Fprintln(os.Stderr, "policy eval: --policy is required")
		fs.Usage()
		return 2
	}

	eng, err := loadEngine(*policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "policy eval:", err)
		return 1
	}

	in, err := evalInput(*reportPath, imageHints{
		ref: *imageRef, registry: *registry, repository: *repository, tag: *tag, digest: *digest,
		signed: *signed, verified: *verified,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "policy eval:", err)
		return 1
	}

	now := time.Now().UTC()
	if *nowStr != "" {
		if ts, err := time.Parse(time.RFC3339, *nowStr); err == nil {
			now = ts
		} else {
			fmt.Fprintln(os.Stderr, "policy eval: invalid --now:", err)
			return 2
		}
	}

	res := eng.Evaluate(in, now)
	var ex *policy.Explanation
	if *explain {
		ex = eng.Explain(res, in)
	}

	if err := renderEval(os.Stdout, *format, res, ex); err != nil {
		fmt.Fprintln(os.Stderr, "policy eval:", err)
		return 1
	}
	if gate(res.Decision, *failOn) {
		return 1
	}
	return 0
}

// imageHints carries the image-identity and attestation flags for eval.
type imageHints struct {
	ref, registry, repository, tag, digest string
	signed, verified                       string
}

// evalInput builds a policy Input from a report file (optional) plus CLI hints.
func evalInput(reportPath string, h imageHints) (*policy.Input, error) {
	in := &policy.Input{Image: policy.Image{
		Reference:  h.ref,
		Registry:   h.registry,
		Repository: h.repository,
		Tag:        h.tag,
		Digest:     h.digest,
	}}
	if reportPath != "" {
		data, err := os.ReadFile(reportPath)
		if err != nil {
			return nil, fmt.Errorf("read report %q: %w", reportPath, err)
		}
		rep, err := policy.LoadReport(data)
		if err != nil {
			return nil, err
		}
		in.Findings = rep.EngineFindings()
		in.Licenses = licensesFromFindings(in.Findings)
		if in.Image.Reference == "" {
			in.Image.Reference = rep.Target
		}
	}
	in.Attest = attestHints(h, in.Findings)
	return in, nil
}

// attestHints resolves signed/verified from flags, inferring from the report
// when neither flag was given.
func attestHints(h imageHints, findings []engine.Finding) policy.AttestationState {
	if h.signed == "" && h.verified == "" {
		return policy.InferAttestation(findings)
	}
	att := policy.StaticAttestation{IsSigned: h.signed == "true"}
	for _, p := range strings.Split(h.verified, ",") {
		if p = strings.TrimSpace(p); p != "" {
			att.Predicates = append(att.Predicates, p)
		}
	}
	return att
}

// gate maps a decision to a CI exit condition.
func gate(d policy.DecisionType, failOn string) bool {
	switch failOn {
	case "never":
		return false
	case "warn":
		return d == policy.DecisionDeny || d == policy.DecisionWarn
	default: // "deny"
		return d == policy.DecisionDeny
	}
}

// --- dsecrat policy test -------------------------------------------------------

// TestCommand implements `dsecrat policy test`: run a committed policy test suite.
func TestCommand(args []string) int {
	fs := flag.NewFlagSet("policy test", flag.ContinueOnError)
	format := fs.String("format", "table", "output format: table|json")
	nowStr := fs.String("now", "", "default evaluation time (RFC3339) for cases without their own")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: dsecrat policy test [flags] <suite.json>\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "policy test: missing <suite.json>")
		fs.Usage()
		return 2
	}
	suitePath := fs.Arg(0)

	data, err := os.ReadFile(suitePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "policy test:", err)
		return 1
	}
	suite, err := policy.ParseSuite(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "policy test:", err)
		return 1
	}

	// The policy path in the suite is relative to the suite file.
	policyPath := suite.Policy
	if !filepath.IsAbs(policyPath) {
		policyPath = filepath.Join(filepath.Dir(suitePath), policyPath)
	}
	eng, err := loadEngine(policyPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "policy test:", err)
		return 1
	}

	now := time.Now().UTC()
	if *nowStr != "" {
		if ts, err := time.Parse(time.RFC3339, *nowStr); err == nil {
			now = ts
		}
	}

	sr := eng.RunSuite(suite.Cases, now)
	if err := renderSuite(os.Stdout, *format, sr); err != nil {
		fmt.Fprintln(os.Stderr, "policy test:", err)
		return 1
	}
	if !sr.OK() {
		return 1
	}
	return 0
}
