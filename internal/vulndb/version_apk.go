package vulndb

import "strings"

// --- Alpine (apk) version comparison ------------------------------------

// apkSuffixRank orders apk's named suffixes. Pre-release suffixes rank *below*
// the plain release (rank 4); post-release suffixes rank above it. This is why
// "1.0_alpha1" < "1.0" < "1.0_p1" in Alpine.
var apkSuffixRank = map[string]int{
	"alpha": 0, "beta": 1, "pre": 2, "rc": 3,
	// (no suffix) == 4 — the release itself
	"cvs": 5, "svn": 6, "git": 7, "hg": 8, "p": 9,
}

const apkReleaseRank = 4

// apkVersion is a parsed Alpine version.
type apkVersion struct {
	numbers  []string    // dot-separated numeric components
	letter   string      // optional single trailing letter, e.g. the "a" in 1.0a
	suffixes []apkSuffix // _alpha1, _p2, …
	revision string      // the N in -rN, "" if absent (treated as 0)
}

type apkSuffix struct {
	rank int
	num  string
}

// compareAPK compares two Alpine package versions. It parses each side into
// numeric components, an optional letter, ordered suffixes, and a build
// revision, then compares them in that priority order.
func compareAPK(a, b string) int {
	av := parseAPK(a)
	bv := parseAPK(b)

	// Numeric components, one at a time; a missing component counts as 0.
	n := len(av.numbers)
	if len(bv.numbers) > n {
		n = len(bv.numbers)
	}
	for i := 0; i < n; i++ {
		ai, bi := "0", "0"
		if i < len(av.numbers) {
			ai = av.numbers[i]
		}
		if i < len(bv.numbers) {
			bi = bv.numbers[i]
		}
		if c := compareNumeric(ai, bi); c != 0 {
			return c
		}
	}
	// Optional trailing letter: present outranks absent.
	if av.letter != bv.letter {
		if c := strings.Compare(av.letter, bv.letter); c != 0 {
			return sign(c)
		}
	}
	// Suffixes, compared pairwise; a missing suffix is the release (rank 4).
	if c := compareAPKSuffixes(av.suffixes, bv.suffixes); c != 0 {
		return c
	}
	// Build revision (-rN); absent counts as 0.
	return compareNumeric(defaultZero(av.revision), defaultZero(bv.revision))
}

func compareAPKSuffixes(a, b []apkSuffix) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		ar, br := apkReleaseRank, apkReleaseRank
		aNum, bNum := "0", "0"
		if i < len(a) {
			ar, aNum = a[i].rank, a[i].num
		}
		if i < len(b) {
			br, bNum = b[i].rank, b[i].num
		}
		if ar != br {
			return sign(ar - br)
		}
		if c := compareNumeric(defaultZero(aNum), defaultZero(bNum)); c != 0 {
			return c
		}
	}
	return 0
}

// parseAPK breaks an apk version string into its components. It is tolerant of
// malformed input: anything it cannot classify is ignored rather than fatal.
func parseAPK(v string) apkVersion {
	var out apkVersion
	// Split off the build revision "-rN".
	if i := strings.LastIndex(v, "-r"); i >= 0 && allDigits(v[i+2:]) {
		out.revision = v[i+2:]
		v = v[:i]
	}
	// Split suffixes off the main version at the first '_'.
	main := v
	if i := strings.IndexByte(v, '_'); i >= 0 {
		main = v[:i]
		out.suffixes = parseAPKSuffixes(v[i:])
	}
	// A single trailing letter (e.g. the "a" in "1.0a"): a lone alpha byte
	// immediately preceded by a digit or dot.
	if n := len(main); n >= 2 && isAlpha(main[n-1]) && (isDigit(main[n-2]) || main[n-2] == '.') {
		out.letter = main[n-1:]
		main = main[:n-1]
	}
	out.numbers = strings.Split(strings.Trim(main, "."), ".")
	return out
}

// parseAPKSuffixes parses a run like "_rc1_p2" into ranked suffixes.
func parseAPKSuffixes(s string) []apkSuffix {
	var out []apkSuffix
	for _, part := range strings.Split(strings.TrimPrefix(s, "_"), "_") {
		if part == "" {
			continue
		}
		name := strings.TrimRightFunc(part, func(r rune) bool { return r >= '0' && r <= '9' })
		num := part[len(name):]
		rank, ok := apkSuffixRank[name]
		if !ok {
			rank = apkReleaseRank // unknown suffix ≈ release-level
		}
		out = append(out, apkSuffix{rank: rank, num: num})
	}
	return out
}

func defaultZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}
