package vulndb

import "strings"

// --- Debian / dpkg version comparison -----------------------------------

// compareDeb implements dpkg's version ordering: an optional numeric epoch, an
// upstream version, and an optional Debian revision, each compared with the
// dpkg "verrevcmp" algorithm. The subtle rules that trip up naive comparators:
// a '~' sorts *before* everything (so "1.0~rc1" < "1.0"), letters sort before
// non-letter punctuation, and digit runs compare numerically regardless of
// zero-padding. Getting the epoch and '~' rules wrong is a classic source of
// both false positives and missed CVEs on Debian/Ubuntu.
func compareDeb(a, b string) int {
	ae, au, ar := splitDeb(a)
	be, bu, br := splitDeb(b)
	if c := compareNumeric(itoaDefault(ae), itoaDefault(be)); c != 0 {
		return c
	}
	if c := debVerRevCmp(au, bu); c != 0 {
		return c
	}
	return debVerRevCmp(ar, br)
}

// splitDeb decomposes "[epoch:]upstream[-revision]" into its three parts.
// A missing epoch defaults to "0"; a missing revision to "0".
func splitDeb(v string) (epoch, upstream, revision string) {
	epoch = "0"
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if e := v[:i]; allDigits(e) {
			epoch = e
			v = v[i+1:]
		}
	}
	revision = "0"
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		upstream = v[:i]
		revision = v[i+1:]
	} else {
		upstream = v
	}
	return epoch, upstream, revision
}

func itoaDefault(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

// debVerRevCmp is dpkg's core comparison over a version fragment: it alternates
// between non-digit and digit runs. Non-digit runs compare character-by-
// character using debOrder (which special-cases '~' and letters); digit runs
// compare numerically.
func debVerRevCmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// Compare a run of non-digit characters.
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := 0, 0
			if i < len(a) {
				ac = debOrder(a[i])
			}
			if j < len(b) {
				bc = debOrder(b[j])
			}
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		// Skip leading zeros of the digit runs.
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		// Compare digit runs by length then value.
		var firstDiff int
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1 // a has a longer digit run ⇒ larger number
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

// debOrder gives dpkg's collation weight for a single character: '~' sorts
// before anything (including end-of-string, modeled as weight 0), letters keep
// their ASCII value, and every other non-digit is pushed above letters.
func debOrder(c byte) int {
	switch {
	case c == '~':
		return -1
	case isAlpha(c):
		return int(c)
	default:
		return int(c) + 256
	}
}
