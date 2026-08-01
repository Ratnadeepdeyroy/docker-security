package sbom

import (
	"path"
	"regexp"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// maxBinClassifyRead bounds how much of a candidate file's contents the
// binary classifier scans for a version string. Interpreter/runtime binaries
// embed their version near the start of a string table, so scanning the
// first few MiB is enough; capping the scan keeps a single oversized
// false-positive-named file (e.g. a multi-gigabyte data blob coincidentally
// named "node") from making the regex scan expensive.
const maxBinClassifyRead = 8 << 20 // 8 MiB

// binaryClassifierName is the FoundBy value recorded for components produced
// by binClassifierCataloger, and the key normalize() uses to identify (and
// suppress redundant) binary-derived hits.
const binaryClassifierName = "binary-classifier"

// binClassifier detects a well-known runtime binary by filename and pulls its
// version out of the binary's embedded strings. Filename gating keeps this
// cheap: the content regex only ever runs on a handful of files per image.
type binClassifier struct {
	nameRe    *regexp.Regexp // matches the file's base name
	versionRe *regexp.Regexp // group 1 = version, run against raw contents
	component string         // canonical component name
	purlType  string         // purl "type" segment (generic for runtimes)
}

// Unlike busybox/openssl/perl/java below, the python and node version regexes
// are not anchored to a runtime-identifying keyword (e.g. "Python "/"node ")
// immediately before the version digits — left that way deliberately rather
// than tightened. CPython's interpreter constructs its printed banner as the
// literal "Python " concatenated with sys.version at runtime; the embedded
// string constant actually present in the binary (what this regex scans) is
// just sys.version itself ("3.9.25 (main, ...)"), with no "Python" token
// adjacent to it. Requiring a keyword here would very likely turn today's
// (rare, low-severity) false-positive risk into a false-negative against
// real interpreter binaries, which is worse. Node's embedded process.version
// string is similarly a bare "vX.Y.Z" with no adjacent "node" token. A
// tighter, framing-aware pattern is possible but needs real interpreter/node
// binaries to validate against rather than hand-built fixtures, so it is
// left as-is here; see .superpowers/sdd/polish/lens2-sbom.md finding 7.
var binClassifiers = []binClassifier{
	{regexp.MustCompile(`^python(\d+(\.\d+)?)?$`),
		regexp.MustCompile(`(\d+\.\d+\.\d+) \(`), "python", "generic"},
	{regexp.MustCompile(`^node(js)?$`),
		regexp.MustCompile(`\bv(\d+\.\d+\.\d+)\b`), "node", "generic"},
	{regexp.MustCompile(`^openssl$`),
		// The 1.0.2 branch outlived the single-letter patch suffix space
		// (a...z) and continued with two-letter suffixes through the final
		// EOL release, 1.0.2zj (e.g. "1.0.2zc"); {0,2} keeps both forms.
		regexp.MustCompile(`OpenSSL (\d+\.\d+\.\d+[a-z]{0,2})`), "openssl", "generic"},
	{regexp.MustCompile(`^busybox$`),
		regexp.MustCompile(`BusyBox v(\d+\.\d+\.\d+)`), "busybox", "generic"},
	{regexp.MustCompile(`^perl(5[\d.]*)?$`),
		// The window between "perl" and the version needs to stretch far enough
		// to cover a real `perl -v` banner, e.g. "This is perl 5, version 40,
		// subversion 1 (v5.40.1)" has ~30 chars between "perl" and "v5.40.1".
		regexp.MustCompile(`\bperl.{0,40}?v?(5\.\d+\.\d+)`), "perl", "generic"},
	{regexp.MustCompile(`^java$`),
		// Legacy Java 8 embeds its version as "1.8.0_NNN[-bXX]"; the "_NNN"
		// update number (not "1.8.0", which is identical across ~400 Java 8
		// updates) is the only part that distinguishes a patched build from a
		// vulnerable one, so it must be captured rather than discarded. The
		// trailing [+_]\d+ is optional so modern OpenJDK 9+ strings like
		// "17.0.9+9" still work, and a bare quoted version with no build
		// suffix (e.g. `java version "17.0.2"`) still matches on its base
		// three-part version alone.
		regexp.MustCompile(`\b(\d+\.\d+\.\d+(?:[_+]\d+)?)`), "java", "generic"},
}

// soClassifier detects a runtime that ships its real version in a shared
// library rather than in the launcher executable. The distro's `python3.9`
// on the PATH is often a small stub with no version string; the actual
// CPython build (and thus the version CVEs are filed against) lives in
// libpython3.9.so.1.0. The major.minor is encoded in the filename and the
// patch level appears as a bare string in the contents.
type soClassifier struct {
	nameRe    *regexp.Regexp // group 1 = major.minor, matched against base name
	component string         // canonical component name
	purlType  string         // purl "type" segment
}

var soClassifiers = []soClassifier{
	{regexp.MustCompile(`^libpython(\d+\.\d+)\.so`), "python", "generic"},
}

// soPatchRe matches any embedded "major.minor.patch" version string in a
// shared library's contents. It is compiled once at package init rather than
// per soClassifier match (regexp.MustCompile parses and builds an NFA on
// every call, which is wasted work when the pattern shape never changes);
// classifyBinary filters the matches down to the one whose major.minor
// agrees with the filename.
var soPatchRe = regexp.MustCompile(`\b(\d+\.\d+\.\d+)\b`)

// classifyBinary inspects one candidate file. base is the file's base name;
// blob is (a prefix of) its contents. Returns the identified component.
func classifyBinary(base string, blob []byte) (Component, bool) {
	lb := strings.ToLower(base)
	for _, c := range binClassifiers {
		if !c.nameRe.MatchString(lb) {
			continue
		}
		m := c.versionRe.FindSubmatch(blob)
		if m == nil {
			continue
		}
		v := string(m[1])
		return Component{
			Type:    TypeApp,
			Name:    c.component,
			Version: v,
			PURL:    purl(c.purlType, "", c.component, v, nil),
		}, true
	}
	for _, c := range soClassifiers {
		m := c.nameRe.FindStringSubmatch(lb)
		if m == nil {
			continue
		}
		mm := m[1] // major.minor from the filename, e.g. "3.9"
		// Only accept a patch-level version that agrees with the filename's
		// major.minor, so an unrelated version string embedded in the library
		// (a bundled dependency, a copyright date look-alike) can't be picked
		// up as CPython's version. Scan for the first embedded x.y.z string
		// whose major.minor prefix matches mm, mirroring what a per-mm regex
		// `\b(mm\.\d+)\b` would have found, without recompiling a regex here.
		v := mm // fall back to major.minor: still useful and CVE-matchable
		prefix := mm + "."
		for _, pm := range soPatchRe.FindAllSubmatch(blob, -1) {
			if strings.HasPrefix(string(pm[1]), prefix) {
				v = string(pm[1])
				break
			}
		}
		return Component{
			Type:    TypeApp,
			Name:    c.component,
			Version: v,
			PURL:    purl(c.purlType, "", c.component, v, nil),
		}, true
	}
	return Component{}, false
}

// matchesKnownRuntimeName reports whether base (already lowercased by the
// caller's convention, but checked case-insensitively here too) matches any
// classifier's filename pattern. It lets the cataloger skip the version-regex
// scan entirely for the overwhelming majority of files in an image.
func matchesKnownRuntimeName(base string) bool {
	base = strings.ToLower(base)
	for _, c := range binClassifiers {
		if c.nameRe.MatchString(base) {
			return true
		}
	}
	for _, c := range soClassifiers {
		if c.nameRe.MatchString(base) {
			return true
		}
	}
	return false
}

// binClassifierCataloger identifies interpreter/runtime binaries (python,
// node, openssl, busybox, perl, java) directly from their file contents. It
// exists because these runtimes are frequently installed by copying a
// prebuilt binary into the image (or built from source) rather than through
// the distro's package manager, so no package-database cataloger ever sees
// them; without this, CVEs against the interpreter/runtime itself would be
// invisible to vulnerability matching.
type binClassifierCataloger struct{}

func (binClassifierCataloger) Name() string { return binaryClassifierName }

func (c binClassifierCataloger) Catalog(tree *oci.FileTree, _ Distro) ([]Component, []Relationship, error) {
	var comps []Component
	for _, f := range tree.Files() {
		base := path.Base(f.Path)
		if !matchesKnownRuntimeName(base) {
			continue
		}
		blob := f.Data
		if int64(len(blob)) > maxBinClassifyRead {
			blob = blob[:maxBinClassifyRead]
		}
		comp, ok := safeClassifyBinary(base, blob)
		if !ok {
			continue
		}
		comp.Source = "/" + f.Path
		comp.FoundBy = c.Name()
		comps = append(comps, comp)
	}
	return comps, nil, nil
}

// classifyBinaryFn indirects classifyBinary so a test can substitute a
// stand-in that panics, proving safeClassifyBinary's recover actually guards
// this call.
var classifyBinaryFn = classifyBinary

// safeClassifyBinary wraps classifyBinaryFn with a recover so a panic while
// scanning one candidate file's attacker-controlled contents skips just that
// file instead of aborting the whole cataloger (and, since catalogers run in
// sequence in generate.go, the whole SBOM).
func safeClassifyBinary(base string, blob []byte) (comp Component, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			comp, ok = Component{}, false
		}
	}()
	return classifyBinaryFn(base, blob)
}
