package imageaudit

import (
	"path"
	"regexp"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// --- Filesystem probes -------------------------------------------------------
//
// A built image's attack surface lives in its files: is there a shell to drop
// into, a package manager to pull new tools with, a setuid binary to pivot
// through? probeFiles answers all three in a single pass so rules and the
// attack-surface score share one traversal and one truth.

// maxExamples bounds how many concrete paths a finding lists. A hostile or
// simply large image can carry thousands of setuid files; the count is what
// matters for scoring, and a handful of examples is enough for a human to act.
const maxExamples = 20

// surfaceProbe is the result of scanning the effective filesystem.
type surfaceProbe struct {
	shells  []string // discovered shell interpreters (sorted, capped)
	pkgMgrs []string // discovered OS package managers (sorted, capped)
	setuid  []string // setuid binaries (sorted, capped)
	setgid  []string // setgid binaries (sorted, capped)
	setuidN int      // total setuid count (may exceed len(setuid))
	setgidN int      // total setgid count
}

// shellNames are basenames that provide an interactive/scriptable shell.
var shellNames = map[string]bool{
	"sh": true, "bash": true, "dash": true, "ash": true,
	"zsh": true, "ksh": true, "busybox": true, "csh": true, "tcsh": true,
}

// pkgMgrNames are OS package-manager basenames. Their presence in a *runtime*
// image is surface: it lets an attacker (or a compromised process) install new
// tooling in place.
var pkgMgrNames = map[string]bool{
	"apt": true, "apt-get": true, "dpkg": true, "apk": true,
	"yum": true, "dnf": true, "microdnf": true, "rpm": true,
	"zypper": true, "pacman": true, "equo": true, "tdnf": true,
}

// probeFiles scans the flattened filesystem once, classifying binaries and
// counting setuid/setgid entries. It is deterministic: inputs arrive path
// sorted (oci.FileTree.Files) and every output slice is bounded and stable.
func probeFiles(files []*oci.File) surfaceProbe {
	var p surfaceProbe
	seenShell := map[string]bool{}
	seenPkg := map[string]bool{}
	for _, f := range files {
		base := path.Base(f.Path)
		inBin := isInBinDir(f.Path)

		if inBin && shellNames[base] && !seenShell[base] {
			seenShell[base] = true
			if len(p.shells) < maxExamples {
				p.shells = append(p.shells, base)
			}
		}
		if inBin && pkgMgrNames[base] && !seenPkg[base] {
			seenPkg[base] = true
			if len(p.pkgMgrs) < maxExamples {
				p.pkgMgrs = append(p.pkgMgrs, base)
			}
		}
		// Special bits live in the low mode bits. NOTE: internal/oci casts the
		// raw tar mode straight to fs.FileMode, so the Go flag fs.ModeSetuid
		// (1<<23) is never set — we must test the Unix bits (0o4000/0o2000)
		// directly or every setuid binary silently slips past.
		mode := uint32(f.Mode)
		if mode&0o4000 != 0 {
			p.setuidN++
			if len(p.setuid) < maxExamples {
				p.setuid = append(p.setuid, f.Path)
			}
		}
		if mode&0o2000 != 0 {
			p.setgidN++
			if len(p.setgid) < maxExamples {
				p.setgid = append(p.setgid, f.Path)
			}
		}
	}
	return p
}

// isInBinDir reports whether a path sits in a conventional executable
// directory, so a data file merely *named* "sh" is not mistaken for a shell.
func isInBinDir(p string) bool {
	dir := path.Dir(p)
	switch dir {
	case "bin", "sbin", "usr/bin", "usr/sbin", "usr/local/bin", "usr/local/sbin":
		return true
	}
	return false
}

// --- Secret heuristics -------------------------------------------------------

// secretKeyRe matches environment-variable names that conventionally hold a
// credential. Kept aligned with the Dockerfile linter so the two phases agree
// on what "looks like a secret".
var secretKeyRe = regexp.MustCompile(`(?i)(pass(word)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|passwd|auth)`)

// secretValueRes match values whose *shape* betrays a specific credential type,
// independent of the variable name — catching e.g. `X=AKIA...` where the key is
// innocuous. Anchored, specific patterns keep the false-positive rate low.
var secretValueRes = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                            // AWS access key id
	regexp.MustCompile(`gh[pousr]_[0-9A-Za-z]{20,}`),                  // GitHub tokens
	regexp.MustCompile(`xox[baprs]-[0-9A-Za-z-]{10,}`),                // Slack tokens
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY`),               // PEM private keys
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.`), // JWTs
}

// splitEnv splits a "KEY=VALUE" entry. A bare "KEY" (no '=') yields an empty
// value, which the caller treats as "declared but unset".
func splitEnv(kv string) (key, value string) {
	if i := strings.IndexByte(kv, '='); i >= 0 {
		return kv[:i], kv[i+1:]
	}
	return kv, ""
}

// secretEnv reports whether an env entry looks like a baked-in credential and,
// if so, why (for the finding description). A key match requires a non-empty
// value — an empty `SECRET=` declares nothing. A value match fires on its own.
func secretEnv(key, value string) (bool, string) {
	if secretKeyRe.MatchString(key) && strings.TrimSpace(value) != "" {
		return true, "the variable name resembles a credential and carries a value"
	}
	for _, re := range secretValueRes {
		if re.MatchString(value) {
			return true, "the value matches a known credential format"
		}
	}
	return false, ""
}
