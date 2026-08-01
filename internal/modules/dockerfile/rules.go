package dockerfile

import (
	"regexp"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// rule inspects a parsed Dockerfile and returns any findings.
type rule func(df *Dockerfile, path string) []engine.Finding

// rules is the ordered rule set. Adding a rule here wires it into the module.
var rules = []rule{
	ruleBaseImageTag,        // DS-RAT-DF-001 / DS-RAT-DF-010
	ruleUserRoot,            // DS-RAT-DF-002
	ruleMissingHealthcheck,  // DS-RAT-DF-003
	ruleAddInsteadOfCopy,    // DS-RAT-DF-004
	ruleAptNoCleanup,        // DS-RAT-DF-005
	ruleSecretInEnvArg,      // DS-RAT-DF-006
	ruleCurlPipeShell,       // DS-RAT-DF-007
	ruleSudo,                // DS-RAT-DF-008
	ruleUnpinnedPackages,    // DS-RAT-DF-011
	ruleNoInstallRecommends, // DS-RAT-DF-012
	rulePipefail,            // DS-RAT-DF-013
}

func mk(id string, sev engine.Severity, title, desc, remediation, path string, line int, refs ...string) engine.Finding {
	return engine.Finding{
		RuleID:      id,
		Module:      moduleName,
		Severity:    sev,
		Title:       title,
		Description: desc,
		Remediation: remediation,
		Resource:    path,
		Location:    &engine.Location{Path: path, StartLine: line, EndLine: line},
		References:  refs,
	}
}

// imageTag extracts the tag from an image reference, or "" if untagged.
// It ignores a "registry:port" colon by requiring the tag to contain no slash.
func imageTag(ref string) string {
	if i := strings.LastIndex(ref, ":"); i >= 0 && !strings.Contains(ref[i+1:], "/") {
		return ref[i+1:]
	}
	return ""
}

// DS-RAT-DF-001: base image uses :latest or is untagged (non-reproducible).
// DS-RAT-DF-010: base image is tagged but not pinned to a digest (informational).
func ruleBaseImageTag(df *Dockerfile, path string) []engine.Finding {
	var out []engine.Finding
	stages := map[string]bool{}
	for _, ins := range df.From() {
		f := strings.Fields(ins.Args)
		if len(f) == 0 {
			continue
		}
		ref := f[0]
		// Record "AS <stage>" aliases so later FROM <stage> is not flagged.
		if len(f) >= 3 && strings.EqualFold(f[1], "AS") {
			stages[strings.ToLower(f[2])] = true
		}
		low := strings.ToLower(ref)
		if stages[low] || low == "scratch" || strings.Contains(ref, "$") {
			continue
		}
		if strings.Contains(ref, "@sha256:") {
			continue // digest-pinned: best practice, nothing to flag
		}
		tag := imageTag(ref)
		switch {
		case tag == "":
			out = append(out, mk("DS-RAT-DF-001", engine.SeverityHigh,
				"Base image is untagged (implicit :latest)",
				"FROM "+ref+" has no tag, so the base resolves to a moving :latest and builds are not reproducible.",
				"Pin the base image to an explicit version tag, ideally a @sha256 digest.",
				path, ins.StartLine, "CIS-DI-0006", "DL3006"))
		case tag == "latest":
			out = append(out, mk("DS-RAT-DF-001", engine.SeverityHigh,
				"Base image pinned to :latest",
				"FROM "+ref+" tracks a moving tag; the base can change under you between builds.",
				"Pin to an explicit version tag, ideally a @sha256 digest.",
				path, ins.StartLine, "DL3007"))
		default:
			out = append(out, mk("DS-RAT-DF-010", engine.SeverityInfo,
				"Base image not pinned to a digest",
				"FROM "+ref+" is tagged but not pinned by @sha256 digest; a repushed tag can silently change the base.",
				"Append @sha256:<digest> to lock the exact base image content.",
				path, ins.StartLine))
		}
	}
	return out
}

// DS-RAT-DF-002: final image runs as root (no USER, or USER root/0). CIS-DI-0001.
func ruleUserRoot(df *Dockerfile, path string) []engine.Finding {
	last := ""
	line := 0
	for _, ins := range df.Instructions {
		if ins.Cmd == "USER" {
			// A bare "USER" line (no argument) has no fields to index; treat
			// it as if no USER were set rather than panicking.
			fields := strings.Fields(ins.Args)
			if len(fields) > 0 {
				last = fields[0]
			} else {
				last = ""
			}
			line = ins.StartLine
		}
	}
	if !df.Has("FROM") {
		return nil
	}
	if last == "" {
		from := df.From()
		l := 1
		if len(from) > 0 {
			l = from[len(from)-1].StartLine
		}
		return []engine.Finding{mk("DS-RAT-DF-002", engine.SeverityMedium,
			"Container runs as root (no USER set)",
			"No USER instruction is present, so the container runs as root by default.",
			"Create and switch to a dedicated non-root user with a USER instruction.",
			path, l, "CIS-DI-0001", "DL3002")}
	}
	if last == "root" || last == "0" {
		return []engine.Finding{mk("DS-RAT-DF-002", engine.SeverityHigh,
			"Container explicitly runs as root",
			"The effective USER is '"+last+"', so processes run with in-container root.",
			"Switch to a non-root UID before the final CMD/ENTRYPOINT.",
			path, line, "CIS-DI-0001", "DL3002")}
	}
	return nil
}

// DS-RAT-DF-003: no HEALTHCHECK instruction. CIS-DI-0006.
func ruleMissingHealthcheck(df *Dockerfile, path string) []engine.Finding {
	if df.Has("HEALTHCHECK") {
		return nil
	}
	line := 1
	if from := df.From(); len(from) > 0 {
		line = from[0].StartLine
	}
	return []engine.Finding{mk("DS-RAT-DF-003", engine.SeverityLow,
		"No HEALTHCHECK instruction",
		"The image declares no HEALTHCHECK, so orchestrators cannot tell whether the container is actually healthy.",
		"Add a HEALTHCHECK that probes the primary process.",
		path, line, "CIS-DI-0006", "DL3057")}
}

// DS-RAT-DF-004: ADD used where COPY is safer, or ADD from a remote URL.
func ruleAddInsteadOfCopy(df *Dockerfile, path string) []engine.Finding {
	var out []engine.Finding
	for _, ins := range df.byCmd("ADD") {
		remote := false
		for _, tok := range strings.Fields(ins.Args) {
			if strings.HasPrefix(tok, "http://") || strings.HasPrefix(tok, "https://") {
				remote = true
			}
		}
		if remote {
			out = append(out, mk("DS-RAT-DF-004", engine.SeverityMedium,
				"ADD fetches a remote URL",
				"ADD with a URL downloads unverified remote content directly into the image.",
				"Use RUN curl/wget with checksum verification, or COPY a vetted local artifact.",
				path, ins.StartLine, "DL3020"))
		} else {
			out = append(out, mk("DS-RAT-DF-004", engine.SeverityLow,
				"ADD used instead of COPY",
				"ADD has implicit tar auto-extraction and URL semantics; COPY is more predictable for local files.",
				"Replace ADD with COPY unless auto-extraction is explicitly required.",
				path, ins.StartLine, "DL3020", "CIS-DI-0009"))
		}
	}
	return out
}

// DS-RAT-DF-005: apt-get install without cache cleanup in the same layer.
func ruleAptNoCleanup(df *Dockerfile, path string) []engine.Finding {
	var out []engine.Finding
	for _, ins := range df.byCmd("RUN") {
		a := ins.Args
		if strings.Contains(a, "apt-get install") || strings.Contains(a, "apt install") {
			if !strings.Contains(a, "rm -rf /var/lib/apt/lists") {
				out = append(out, mk("DS-RAT-DF-005", engine.SeverityLow,
					"apt-get install without cache cleanup",
					"Package lists are left in the layer, bloating the image and enlarging its attack surface.",
					"Append '&& rm -rf /var/lib/apt/lists/*' (and consider --no-install-recommends) in the same RUN.",
					path, ins.StartLine, "DL3009"))
			}
		}
	}
	return out
}

var secretKeyRe = regexp.MustCompile(`(?i)(pass(word)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)`)

// DS-RAT-DF-006: a secret-looking value baked into ENV or ARG. CIS-DI-0010.
func ruleSecretInEnvArg(df *Dockerfile, path string) []engine.Finding {
	var out []engine.Finding
	check := func(ins Instruction) {
		// Look at the key name(s) in "KEY=value" or "KEY value" forms.
		for _, pair := range strings.Fields(ins.Args) {
			key := pair
			hasVal := false
			if i := strings.Index(pair, "="); i >= 0 {
				key = pair[:i]
				hasVal = strings.TrimSpace(pair[i+1:]) != ""
			}
			if secretKeyRe.MatchString(key) && (hasVal || ins.Cmd == "ARG") {
				out = append(out, mk("DS-RAT-DF-006", engine.SeverityHigh,
					"Possible secret in "+ins.Cmd+" ("+key+")",
					ins.Cmd+" "+key+" looks like a credential; values here persist in image history and metadata.",
					"Never bake secrets into ENV/ARG. Use BuildKit --mount=type=secret or a runtime secret store.",
					path, ins.StartLine, "CIS-DI-0010"))
				return
			}
		}
	}
	for _, ins := range df.byCmd("ENV") {
		check(ins)
	}
	for _, ins := range df.byCmd("ARG") {
		check(ins)
	}
	return out
}

var pipeShellRe = regexp.MustCompile(`(?i)(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba)?sh`)

// DS-RAT-DF-007: piping a downloaded script straight into a shell.
func ruleCurlPipeShell(df *Dockerfile, path string) []engine.Finding {
	var out []engine.Finding
	for _, ins := range df.byCmd("RUN") {
		if pipeShellRe.MatchString(ins.Args) {
			out = append(out, mk("DS-RAT-DF-007", engine.SeverityMedium,
				"Remote script piped into a shell",
				"A downloaded script is executed unverified (curl|sh), a classic supply-chain injection point.",
				"Download to a file, verify a checksum/signature, then execute.",
				path, ins.StartLine))
		}
	}
	return out
}

var (
	// The pre-"install" option-token group tolerates arbitrary option tokens
	// (e.g. apt's "-o Dpkg::Options::=\"--force-confdef\"", which has
	// uppercase letters, ':', '=' and quotes) by only excluding whitespace and
	// the shell separators ("&", "|", ";") that mark the end of this
	// invocation - those separators must still stop the prefix scan so a
	// chained "apt-get update && apt-get install ..." keeps matching each
	// install invocation independently instead of one swallowing the next.
	aptInstallRe = regexp.MustCompile(`\bapt(-get)?\s+(?:[^\s&|;]+\s+)*install\b([^&|;]*)`)
	apkAddRe     = regexp.MustCompile(`\bapk\s+(?:[a-z-]+\s+)*add\b([^&|;]*)`)
	pipInstallRe = regexp.MustCompile(`\bpip3?\s+install\b([^&|;]*)`)
)

// valueConsumingFlags are flags whose following token is an option value
// (a path, a requirements file, a target release, ...) rather than a
// package name, e.g. "pip install -r requirements.txt" or "pip install -e .".
var valueConsumingFlags = map[string]bool{
	"-r": true, "--requirement": true,
	"-e": true, "--editable": true,
	"-c": true, "--constraint": true,
	"-t": true, "--target": true,
	// apk's "--virtual <name>" names a disposable meta-package group (e.g.
	// ".build-deps") whose value is never a real installable package.
	"--virtual": true,
}

// packagesOf splits an install argument tail into package tokens, dropping
// flags (-y, --no-install-recommends), the values consumed by flags like -r/
// -e/-c/-t, and bare paths / requirement files (., ./, *.txt) that are not
// actual package names.
func packagesOf(tail string) []string {
	var pkgs []string
	skipNext := false
	for _, tok := range strings.Fields(tail) {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(tok, "-") {
			if valueConsumingFlags[tok] {
				skipNext = true
			}
			continue
		}
		if tok == "install" || tok == "." || strings.Contains(tok, "/") || strings.HasSuffix(tok, ".txt") {
			continue
		}
		pkgs = append(pkgs, tok)
	}
	return pkgs
}

// DS-RAT-DF-011: package installs without version pins are not reproducible and
// silently pick up new (possibly vulnerable or breaking) versions.
func ruleUnpinnedPackages(df *Dockerfile, path string) []engine.Finding {
	var out []engine.Finding
	type mgr struct {
		re  *regexp.Regexp
		pin string // substring that indicates a pinned package
		fix string
	}
	managers := []mgr{
		{aptInstallRe, "=", "apt-get install <pkg>=<version>"},
		{apkAddRe, "=", "apk add <pkg>=<version>"},
		{pipInstallRe, "==", "pip install <pkg>==<version>"},
	}
	for _, ins := range df.byCmd("RUN") {
		args := ins.Args
		for _, m := range managers {
			// A single RUN can chain several installs (a && b && c); inspect
			// every invocation of this manager, not just the first match.
			subs := m.re.FindAllStringSubmatch(args, -1)
			if subs == nil {
				continue
			}
			sawPkg := false
			unpinned := false
			for _, sub := range subs {
				for _, p := range packagesOf(sub[len(sub)-1]) {
					sawPkg = true
					if !strings.Contains(p, m.pin) {
						unpinned = true
					}
				}
			}
			if !sawPkg {
				continue
			}
			if unpinned {
				out = append(out, mk("DS-RAT-DF-011", engine.SeverityLow,
					"Package install without version pin",
					"A package manager install in this RUN does not pin package versions, so rebuilds are not reproducible and can silently pull vulnerable or breaking releases.",
					"Pin every package: "+m.fix+".",
					path, ins.StartLine, "DL3008", "DL3018", "DL3013"))
			}
		}
	}
	return out
}

// DS-RAT-DF-012: apt-get install without --no-install-recommends bloats the image
// with packages nobody audited.
func ruleNoInstallRecommends(df *Dockerfile, path string) []engine.Finding {
	var out []engine.Finding
	for _, ins := range df.byCmd("RUN") {
		// Evaluate each apt-get/apt install invocation in this RUN
		// independently: a chained RUN (a && b) can have the flag on one
		// install and not another, so a whole-string Contains check would
		// miss the offending invocation.
		matches := aptInstallRe.FindAllStringSubmatch(ins.Args, -1)
		if matches == nil {
			continue
		}
		missing := false
		for _, m := range matches {
			if !strings.Contains(m[0], "--no-install-recommends") {
				missing = true
			}
		}
		if missing {
			out = append(out, mk("DS-RAT-DF-012", engine.SeverityLow,
				"apt-get install without --no-install-recommends",
				"Recommended packages are pulled in implicitly, growing the attack surface with software nobody asked for.",
				"Add --no-install-recommends to every apt-get install.",
				path, ins.StartLine, "DL3015"))
		}
	}
	return out
}

// quotedSpanRe matches single- or double-quoted substrings so they can be
// stripped before scanning for a bare pipe. This kills the two most common
// false positives in rulePipefail: sed's alternate-delimiter idiom
// ('s|foo|bar|g') and literal '|' characters inside echoed/printed text
// ("a|b"), neither of which is an actual shell pipeline.
var quotedSpanRe = regexp.MustCompile(`'[^']*'|"[^"]*"`)

// DS-RAT-DF-013: a RUN with a pipe under the default shell ignores upstream
// failures (`curl | sh` "succeeds" even when curl fails).
func rulePipefail(df *Dockerfile, path string) []engine.Finding {
	var out []engine.Finding
	pipefail := false
	for _, ins := range df.Instructions {
		switch ins.Cmd {
		case "SHELL":
			pipefail = strings.Contains(ins.Args, "pipefail")
		case "FROM":
			pipefail = false // each stage resets the shell
		case "RUN":
			// Exec-form RUN (JSON array) has no shell, hence no pipe semantics.
			if strings.HasPrefix(strings.TrimSpace(ins.Args), "[") {
				continue
			}
			// Detect a real, unguarded pipe: first drop quoted spans so a
			// literal '|' inside a string (sed's 's|a|b|g', echo "a|b", ...)
			// isn't mistaken for a pipeline, then strip out "||" pairs so an
			// unrelated "|| true" fallback elsewhere in the command doesn't
			// mask a genuine pipeline (e.g. "curl ... | sh || true" still has
			// a lone "|").
			unquoted := quotedSpanRe.ReplaceAllString(ins.Args, "")
			stripped := strings.ReplaceAll(unquoted, "||", "")
			if strings.Contains(stripped, "|") && !pipefail {
				out = append(out, mk("DS-RAT-DF-013", engine.SeverityLow,
					"RUN uses a pipe without pipefail",
					"Under the default shell the exit status of a pipeline is the last command's, so an upstream download/tool failure is silently ignored.",
					"Precede piped RUNs with: SHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"] (or ash equivalent).",
					path, ins.StartLine, "DL4006"))
			}
		}
	}
	return out
}

// DS-RAT-DF-008: sudo used inside the image (container anti-pattern).
func ruleSudo(df *Dockerfile, path string) []engine.Finding {
	var out []engine.Finding
	for _, ins := range df.byCmd("RUN") {
		for _, tok := range strings.Fields(ins.Args) {
			if tok == "sudo" {
				out = append(out, mk("DS-RAT-DF-008", engine.SeverityLow,
					"sudo used in RUN instruction",
					"sudo is unnecessary in image builds and can lead to unexpected privilege behavior.",
					"Run build steps as the needed user directly; avoid sudo in containers.",
					path, ins.StartLine, "DL3004"))
				break
			}
		}
	}
	return out
}
