package vulndb

import "strings"

// --- semver (npm, cargo, composer, nuget, and the Go base scheme) --------

// compareSemver implements Semantic Versioning 2.0.0 precedence. Release
// components are compared numerically; a pre-release version is *lower* than the
// associated release; build metadata (after '+') is ignored for ordering. This
// is the ordering npm, Cargo, NuGet and (via compareGo) Go rely on.
func compareSemver(a, b string) int {
	a = strings.TrimPrefix(strings.TrimPrefix(a, "v"), "V")
	b = strings.TrimPrefix(strings.TrimPrefix(b, "v"), "V")
	// Drop build metadata; it never affects precedence.
	a = cutAt(a, '+')
	b = cutAt(b, '+')

	aCore, aPre, _ := strings.Cut(a, "-")
	bCore, bPre, _ := strings.Cut(b, "-")

	if c := compareDotted(aCore, bCore); c != 0 {
		return c
	}
	// Equal cores: a version WITH a pre-release ranks below one without.
	switch {
	case aPre == "" && bPre == "":
		return 0
	case aPre == "":
		return 1
	case bPre == "":
		return -1
	}
	return comparePreRelease(aPre, bPre)
}

// compareDotted compares dot-separated numeric release fields (e.g. "1.2.0"),
// treating a missing field as 0 so "1.2" == "1.2.0".
func compareDotted(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		av, bv := "0", "0"
		if i < len(as) && as[i] != "" {
			av = as[i]
		}
		if i < len(bs) && bs[i] != "" {
			bv = bs[i]
		}
		// Numeric where possible; fall back to lexical for odd fields.
		if allDigits(av) && allDigits(bv) {
			if c := compareNumeric(av, bv); c != 0 {
				return c
			}
			continue
		}
		if c := strings.Compare(av, bv); c != 0 {
			return sign(c)
		}
	}
	return 0
}

// comparePreRelease compares the dot-separated identifiers of two SemVer
// pre-release strings: numeric identifiers compare numerically and rank below
// alphanumeric ones; a larger set of identifiers outranks a prefix of it.
func comparePreRelease(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		ai, bi := as[i], bs[i]
		aNum, bNum := allDigits(ai), allDigits(bi)
		switch {
		case aNum && bNum:
			if c := compareNumeric(ai, bi); c != 0 {
				return c
			}
		case aNum: // numeric < alphanumeric
			return -1
		case bNum:
			return 1
		default:
			if c := strings.Compare(ai, bi); c != 0 {
				return sign(c)
			}
		}
	}
	return sign(len(as) - len(bs))
}

// cutAt returns the substring before the first occurrence of sep, or the whole
// string if sep is absent.
func cutAt(s string, sep byte) string {
	if i := strings.IndexByte(s, sep); i >= 0 {
		return s[:i]
	}
	return s
}

// allDigits reports whether s is non-empty and entirely ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}
