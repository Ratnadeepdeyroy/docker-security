package imageaudit

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// This file holds the rules that reason over the *filesystem* and the *layer
// history*, as opposed to the config-only rules in rules.go. They share the
// one-pass probe computed in Analyze (ac.probe).

// --- DS-RAT-IMG-005: setuid / setgid binaries ------------------------------------

// ruleSetuid flags setuid/setgid binaries. Each is a local-privilege-escalation
// primitive; a hardened image carries none it does not strictly need.
// CIS-DI-0008. NOTE the detection quirk documented in probeFiles: the special
// bits are read from the raw Unix mode, not fs.ModeSetuid.
func ruleSetuid(ac *auditContext) []engine.Finding {
	p := ac.probe
	if p.setuidN == 0 && p.setgidN == 0 {
		return nil
	}
	var out []engine.Finding
	if p.setuidN > 0 {
		out = append(out, mk("DS-RAT-IMG-005", engine.SeverityMedium, ac.name,
			fmt.Sprintf("%d setuid binaries present", p.setuidN),
			fmt.Sprintf("The image contains %d setuid binaries (%s). Each runs as its file owner regardless of the invoking user, a classic privilege-escalation primitive.", p.setuidN, examples(p.setuid)),
			"Strip the setuid bit from binaries that do not need it (chmod u-s) or remove them; prefer capabilities over setuid where a privilege is genuinely required.",
			"CIS-DI-0008", "MITRE-ATT&CK-T1548.001"))
	}
	if p.setgidN > 0 {
		out = append(out, mk("DS-RAT-IMG-005", engine.SeverityLow, ac.name,
			fmt.Sprintf("%d setgid binaries present", p.setgidN),
			fmt.Sprintf("The image contains %d setgid binaries (%s), which run with their file group and can widen access.", p.setgidN, examples(p.setgid)),
			"Remove the setgid bit (chmod g-s) from binaries that do not require it.",
			"CIS-DI-0008"))
	}
	return out
}

// examples renders a bounded, comma-joined sample of paths for a description.
func examples(paths []string) string {
	if len(paths) == 0 {
		return "none listed"
	}
	shown := paths
	suffix := ""
	if len(shown) > 5 {
		shown = shown[:5]
		suffix = ", ..."
	}
	return strings.Join(shown, ", ") + suffix
}

// --- DS-RAT-IMG-010: package manager present -------------------------------------

// rulePackageManager flags an OS package manager left in a runtime image. It
// lets a compromised process pull in new tooling in place, and its presence
// usually means build-time packages were not pruned.
func rulePackageManager(ac *auditContext) []engine.Finding {
	if len(ac.probe.pkgMgrs) == 0 {
		return nil
	}
	return []engine.Finding{mk("DS-RAT-IMG-010", engine.SeverityLow, ac.name,
		"Package manager present in runtime image",
		"The image ships package manager(s): "+strings.Join(ac.probe.pkgMgrs, ", ")+". In a runtime image these are attack surface — they let an attacker install tooling — and signal that build dependencies were not pruned.",
		"Use a multi-stage build so the runtime stage carries no package manager, or switch to a distroless/minimal base.",
		"CIS-DI-0008", "NIST-SP-800-190")}
}

// --- DS-RAT-IMG-011: shell surface / distroless reward ---------------------------

// ruleShellSurface reports on the shell surface. A shell present in the runtime
// image is a low-severity note (it is what most exploits pivot through). When
// neither a shell nor a package manager is present the image is effectively
// distroless: we emit a positive INFO finding so the good state is visible and
// scoreable, not merely the absence of complaints.
func ruleShellSurface(ac *auditContext) []engine.Finding {
	p := ac.probe
	if len(p.shells) > 0 {
		return []engine.Finding{mk("DS-RAT-IMG-011", engine.SeverityLow, ac.name,
			"Shell present in image",
			"The image contains shell(s): "+strings.Join(p.shells, ", ")+". A shell is the usual pivot for command injection and post-exploitation; shell-less (distroless) runtimes deny that primitive.",
			"If the application does not need a shell at runtime, move to a distroless/scratch base so no shell ships in the final image.",
			"NIST-SP-800-190")}
	}
	if len(p.pkgMgrs) == 0 {
		return []engine.Finding{mk("DS-RAT-IMG-011", engine.SeverityInfo, ac.name,
			"Distroless/minimal runtime detected",
			"The image contains no shell and no package manager, so it is effectively distroless. Command-injection and install-in-place primitives are absent — a strong hardening posture.",
			"Maintain this posture: keep build tooling in earlier stages and out of the runtime image.",
			"NIST-SP-800-190")}
	}
	return nil
}

// --- DS-RAT-IMG-009: dangerous instructions in layer history ---------------------

// historyPattern is a named signature we look for in build-history commands.
type historyPattern struct {
	name     string
	re       *regexp.Regexp
	severity engine.Severity
	title    string
	desc     string
	remedy   string
	refs     []string
}

var historyPatterns = []historyPattern{
	{
		name:     "secret",
		re:       regexp.MustCompile(`(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)\s*[=:]\s*\S`),
		severity: engine.SeverityHigh,
		title:    "Secret assigned in build history",
		desc:     "A build step assigned a credential-shaped value. Image history is readable by anyone with the image, so the secret persists even if a later layer removes it.",
		remedy:   "Rotate the value. Inject secrets at build time with BuildKit --mount=type=secret (never ENV/ARG) and at run time via a secret store.",
		refs:     []string{"CIS-DI-0010"},
	},
	{
		name:     "pipe-to-shell",
		re:       regexp.MustCompile(`(?i)(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba)?sh`),
		severity: engine.SeverityMedium,
		title:    "Remote script piped into a shell during build",
		desc:     "A build step downloaded a script and executed it unverified (curl|sh) — a supply-chain injection point baked into the image lineage.",
		remedy:   "Download to a file, verify a checksum or signature, then execute.",
		refs:     []string{"MITRE-ATT&CK-T1059"},
	},
	{
		name:     "chmod-777",
		re:       regexp.MustCompile(`chmod\s+(-[A-Za-z]+\s+)*(777|a?\+rwx|o\+w)`),
		severity: engine.SeverityLow,
		title:    "World-writable permissions set during build",
		desc:     "A build step made files world-writable (chmod 777 / a+rwx). World-writable files let any in-container user tamper with them.",
		remedy:   "Grant the least permission the process needs; avoid 777.",
		refs:     []string{"CIS-DI-0008"},
	},
	{
		name:     "add-remote",
		re:       regexp.MustCompile(`(?i)\bADD\s+https?://`),
		severity: engine.SeverityLow,
		title:    "Remote artifact fetched via ADD during build",
		desc:     "A build step used ADD with a URL, pulling unverified remote content directly into the image.",
		remedy:   "Fetch with checksum verification, or COPY a vetted local artifact.",
		refs:     []string{"CIS-DI-0009"},
	},
}

// maxHistorySnippet bounds how much of a build command we quote in a finding,
// so a pathological single-line history entry cannot bloat the report.
const maxHistorySnippet = 200

// ruleHistory mines the build history for dangerous instructions. It reports at
// most one finding per signature (the first hit), keeping the report readable
// on images with long, repetitive histories.
func ruleHistory(ac *auditContext) []engine.Finding {
	fired := map[string]bool{}
	var out []engine.Finding
	for _, h := range ac.cfg.History {
		line := h.CreatedBy
		if line == "" {
			line = h.Comment
		}
		if line == "" {
			continue
		}
		for _, p := range historyPatterns {
			if fired[p.name] || !p.re.MatchString(line) {
				continue
			}
			fired[p.name] = true
			out = append(out, mk("DS-RAT-IMG-009", p.severity, snippet(line),
				p.title, p.desc, p.remedy, p.refs...))
		}
	}
	return out
}

// snippet trims a build-command line to a bounded, single-line resource string.
func snippet(s string) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > maxHistorySnippet {
		s = s[:maxHistorySnippet] + "…"
	}
	return s
}

// --- DS-RAT-IMG-012: recoverable removed secrets ---------------------------------

// secretFileRe matches paths that a removed-but-recoverable finding treats as
// sensitive: key material, credential stores, and dotfiles that commonly hold
// tokens.
var secretFileRe = regexp.MustCompile(`(?i)(^|/)(\.?(env|npmrc|netrc|pgpass|git-credentials)|id_[a-z]+|.*\.pem|.*\.key|.*\.p12|.*\.pfx|shadow|htpasswd|credentials|secrets?)($|/|\.)`)

// ruleRecoverableRemoved catches the classic layered-image mistake: a secret
// added in one layer and "deleted" in a later one. The delete is only a
// whiteout — the bytes still sit in the earlier layer's blob and are trivially
// recovered by unpacking that layer. We report only removals that *look*
// sensitive, to avoid drowning the signal. CIS-DI-0010.
func ruleRecoverableRemoved(ac *auditContext) []engine.Finding {
	added := map[string]*oci.File{} // path -> earliest layer file that introduced it
	fired := map[string]bool{}
	var out []engine.Finding

	for _, layer := range ac.img.Layers {
		// First, resolve this layer's whiteouts against everything added below.
		for _, e := range layer.Files {
			base := path.Base(e.Path)
			if base == whiteoutOpaque || !strings.HasPrefix(base, whiteoutPrefix) {
				continue
			}
			target := path.Join(path.Dir(e.Path), strings.TrimPrefix(base, whiteoutPrefix))
			prev, ok := added[target]
			if !ok || fired[target] {
				continue
			}
			if sensitiveRemoval(target, prev) {
				fired[target] = true
				out = append(out, mk("DS-RAT-IMG-012", engine.SeverityHigh, target,
					"Sensitive file deleted in a later layer is still recoverable",
					"The image adds "+target+" in one layer and removes it in a later one, but the delete is only a whiteout marker: the original bytes remain in the earlier layer and can be recovered by unpacking it.",
					"Never add a secret to any layer. If one was committed, rebuild the image from a clean history (BuildKit secret mounts / multi-stage) and rotate the exposed credential.",
					"CIS-DI-0010", "MITRE-ATT&CK-T1552.001"))
			}
		}
		// Then record this layer's regular files as recoverable content.
		for _, e := range layer.Files {
			base := path.Base(e.Path)
			if base == whiteoutOpaque || strings.HasPrefix(base, whiteoutPrefix) {
				continue
			}
			if _, seen := added[e.Path]; !seen {
				added[e.Path] = e
			}
		}
	}
	return out
}

// sensitiveRemoval reports whether a removed file is worth flagging: either its
// path looks like credential material or its recoverable content matches a
// known credential format.
func sensitiveRemoval(target string, f *oci.File) bool {
	if secretFileRe.MatchString(target) {
		return true
	}
	for _, re := range secretValueRes {
		if re.Match(f.Data) {
			return true
		}
	}
	return false
}

// whiteout constants mirror internal/oci's layer semantics. They are duplicated
// (not exported from oci) because they are part of the on-wire tar convention,
// not oci's API; keeping our own copy avoids coupling to an unexported symbol.
const (
	whiteoutPrefix = ".wh."
	whiteoutOpaque = ".wh..wh..opq"
)
