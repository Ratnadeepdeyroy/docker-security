package policy

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Builtins --------------------------------------------------------------
//
// These tables define the entire vocabulary a policy author can use. Keeping
// them declarative (name -> arity + implementation) means the compiler can
// validate a rule's identifiers and call arities before the policy is ever
// deployed, so a typo like `severity_cont("high")` fails at load time with a
// clear message rather than silently never matching at a gate.
//
// Every builtin is a pure function of the Input. None reads the clock, the
// network, or the filesystem — that is what keeps a decision reproducible.

// evalEnv is the per-evaluation environment: the Input plus a cache of compiled
// regexes so a rule that scans findings does not recompile its pattern per row.
type evalEnv struct {
	in     *Input
	regexp map[string]*regexp.Regexp
}

func newEvalEnv(in *Input) *evalEnv {
	return &evalEnv{in: in, regexp: map[string]*regexp.Regexp{}}
}

// compileRegexp compiles (and caches) a pattern. RE2 (Go's regexp) has no
// catastrophic backtracking, so an attacker-supplied resource string cannot
// wedge evaluation.
func (e *evalEnv) compileRegexp(pattern string) (*regexp.Regexp, error) {
	if re, ok := e.regexp[pattern]; ok {
		return re, nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regexp %q: %w", pattern, err)
	}
	e.regexp[pattern] = re
	return re, nil
}

// variable is a nullary binding (an identifier used without parentheses).
type variable struct {
	doc string
	fn  func(env *evalEnv) (Value, error)
}

// builtin is a function binding with a fixed arity.
type builtin struct {
	arity int
	doc   string
	fn    func(env *evalEnv, args []Value) (Value, error)
}

// variables are the bare identifiers available to rules.
var variables = map[string]variable{
	"signed": {"image carries a verified signature", func(e *evalEnv) (Value, error) {
		return Bool(e.in.attestOf().Signed()), nil
	}},
	"digest_pinned": {"image reference is pinned to a digest", func(e *evalEnv) (Value, error) {
		return Bool(e.in.Image.Digest != ""), nil
	}},
	"registry": {"image registry host", func(e *evalEnv) (Value, error) {
		return Str(e.in.Image.Registry), nil
	}},
	"repository": {"image repository path", func(e *evalEnv) (Value, error) {
		return Str(e.in.Image.Repository), nil
	}},
	"tag": {"image tag", func(e *evalEnv) (Value, error) {
		return Str(e.in.Image.Tag), nil
	}},
	"digest": {"image manifest digest", func(e *evalEnv) (Value, error) {
		return Str(e.in.Image.Digest), nil
	}},
	"image_ref": {"full image reference", func(e *evalEnv) (Value, error) {
		return Str(e.in.Image.Reference), nil
	}},
	"finding_count": {"total number of findings", func(e *evalEnv) (Value, error) {
		return Num(float64(len(e.in.Findings))), nil
	}},
	"max_severity": {"highest finding severity present (string)", func(e *evalEnv) (Value, error) {
		return Str(maxSeverity(e.in.Findings)), nil
	}},
	"workload_present": {"a Kubernetes workload spec was provided", func(e *evalEnv) (Value, error) {
		return Bool(e.in.Workload.Present), nil
	}},
	"privileged": {"any container runs privileged", func(e *evalEnv) (Value, error) {
		return Bool(e.in.Workload.Privileged), nil
	}},
	"runs_as_root": {"workload runs as root (uid 0 / not runAsNonRoot)", func(e *evalEnv) (Value, error) {
		return Bool(e.in.Workload.RunAsRoot), nil
	}},
	"host_network": {"workload uses the host network namespace", func(e *evalEnv) (Value, error) {
		return Bool(e.in.Workload.HostNetwork), nil
	}},
	"host_pid": {"workload uses the host PID namespace", func(e *evalEnv) (Value, error) {
		return Bool(e.in.Workload.HostPID), nil
	}},
	"host_ipc": {"workload uses the host IPC namespace", func(e *evalEnv) (Value, error) {
		return Bool(e.in.Workload.HostIPC), nil
	}},
	"read_only_root_fs": {"root filesystem is read-only", func(e *evalEnv) (Value, error) {
		return Bool(e.in.Workload.ReadOnlyRootFS), nil
	}},
	"allow_privilege_escalation": {"privilege escalation is allowed", func(e *evalEnv) (Value, error) {
		return Bool(e.in.Workload.AllowPrivilegeEscalation), nil
	}},
	"uses_host_path": {"workload mounts a hostPath volume", func(e *evalEnv) (Value, error) {
		return Bool(e.in.Workload.UsesHostPath), nil
	}},
}

// functions are the callable builtins.
var functions = map[string]builtin{
	"severity_count": {1, "count of findings at exactly the given severity", func(e *evalEnv, a []Value) (Value, error) {
		s, err := strArg("severity_count", a[0])
		if err != nil {
			return Value{}, err
		}
		return Num(float64(countSeverity(e.in.Findings, engine.ParseSeverity(s), false))), nil
	}},
	"severity_atleast": {1, "count of findings at or above the given severity", func(e *evalEnv, a []Value) (Value, error) {
		s, err := strArg("severity_atleast", a[0])
		if err != nil {
			return Value{}, err
		}
		return Num(float64(countSeverity(e.in.Findings, engine.ParseSeverity(s), true))), nil
	}},
	"has_rule": {1, "a finding with the given rule id exists", func(e *evalEnv, a []Value) (Value, error) {
		id, err := strArg("has_rule", a[0])
		if err != nil {
			return Value{}, err
		}
		for _, f := range e.in.Findings {
			if f.RuleID == id {
				return Bool(true), nil
			}
		}
		return Bool(false), nil
	}},
	"module_count": {1, "count of findings emitted by the given module", func(e *evalEnv, a []Value) (Value, error) {
		name, err := strArg("module_count", a[0])
		if err != nil {
			return Value{}, err
		}
		n := 0
		for _, f := range e.in.Findings {
			if f.Module == name {
				n++
			}
		}
		return Num(float64(n)), nil
	}},
	"resource_matches": {1, "any finding resource matches the given regexp", func(e *evalEnv, a []Value) (Value, error) {
		pat, err := strArg("resource_matches", a[0])
		if err != nil {
			return Value{}, err
		}
		re, err := e.compileRegexp(pat)
		if err != nil {
			return Value{}, err
		}
		for _, f := range e.in.Findings {
			if re.MatchString(f.Resource) {
				return Bool(true), nil
			}
		}
		return Bool(false), nil
	}},
	"verified": {1, "an attestation of the given predicate type is verified", func(e *evalEnv, a []Value) (Value, error) {
		pt, err := strArg("verified", a[0])
		if err != nil {
			return Value{}, err
		}
		return Bool(e.in.attestOf().Verified(pt)), nil
	}},
	"has_license": {1, "the SBOM contains the given SPDX license id", func(e *evalEnv, a []Value) (Value, error) {
		lic, err := strArg("has_license", a[0])
		if err != nil {
			return Value{}, err
		}
		return Bool(containsFold(e.in.Licenses, lic)), nil
	}},
	"has_package": {1, "the SBOM contains a package with the given name", func(e *evalEnv, a []Value) (Value, error) {
		name, err := strArg("has_package", a[0])
		if err != nil {
			return Value{}, err
		}
		return Bool(contains(e.in.Packages, name)), nil
	}},
	"has_capability": {1, "the workload adds the given Linux capability", func(e *evalEnv, a []Value) (Value, error) {
		cap, err := strArg("has_capability", a[0])
		if err != nil {
			return Value{}, err
		}
		return Bool(containsFold(e.in.Workload.Capabilities, cap)), nil
	}},
	"in": {2, "membership: in(x, [a, b, c])", func(e *evalEnv, a []Value) (Value, error) {
		ok, err := a[1].Contains(a[0])
		return Bool(ok), err
	}},
	"matches": {2, "matches(s, regexp)", func(e *evalEnv, a []Value) (Value, error) {
		s, err := strArg("matches", a[0])
		if err != nil {
			return Value{}, err
		}
		pat, err := strArg("matches", a[1])
		if err != nil {
			return Value{}, err
		}
		re, err := e.compileRegexp(pat)
		if err != nil {
			return Value{}, err
		}
		return Bool(re.MatchString(s)), nil
	}},
	"lower": {1, "lower(s): lowercase a string", func(e *evalEnv, a []Value) (Value, error) {
		s, err := strArg("lower", a[0])
		if err != nil {
			return Value{}, err
		}
		return Str(strings.ToLower(s)), nil
	}},
	"startswith": {2, "startswith(s, prefix)", func(e *evalEnv, a []Value) (Value, error) {
		s, err := strArg("startswith", a[0])
		if err != nil {
			return Value{}, err
		}
		pre, err := strArg("startswith", a[1])
		if err != nil {
			return Value{}, err
		}
		return Bool(strings.HasPrefix(s, pre)), nil
	}},
	"endswith": {2, "endswith(s, suffix)", func(e *evalEnv, a []Value) (Value, error) {
		s, err := strArg("endswith", a[0])
		if err != nil {
			return Value{}, err
		}
		suf, err := strArg("endswith", a[1])
		if err != nil {
			return Value{}, err
		}
		return Bool(strings.HasSuffix(s, suf)), nil
	}},
}

// --- helpers ---------------------------------------------------------------

// strArg extracts a string argument, giving a builtin a uniform type error.
func strArg(fn string, v Value) (string, error) {
	if v.Kind != KindStr {
		return "", fmt.Errorf("%s: expected string argument, got %s", fn, v.Kind)
	}
	return v.s, nil
}

// countSeverity counts findings at exactly (or, when atLeast, at/above) sev. A
// threshold that does not parse (SeverityUnknown) counts nothing rather than
// everything, so a typo in a policy fails safe toward "no match".
func countSeverity(fs []engine.Finding, sev engine.Severity, atLeast bool) int {
	if sev == engine.SeverityUnknown {
		return 0
	}
	n := 0
	for _, f := range fs {
		if (atLeast && f.Severity >= sev) || (!atLeast && f.Severity == sev) {
			n++
		}
	}
	return n
}

// maxSeverity returns the string name of the highest severity present.
func maxSeverity(fs []engine.Finding) string {
	h := engine.SeverityUnknown
	for _, f := range fs {
		if f.Severity > h {
			h = f.Severity
		}
	}
	return h.String()
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func containsFold(ss []string, want string) bool {
	for _, s := range ss {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}
