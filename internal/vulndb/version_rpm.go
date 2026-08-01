package vulndb

import "strings"

// --- RPM (EVR) version comparison ---------------------------------------

// compareRPM compares two RPM versions in "[epoch:]version-release" form using
// the rpmvercmp algorithm. Highlights that a naive comparator gets wrong:
// a '~' segment sorts before everything (used for pre-releases, e.g.
// "1.0~beta" < "1.0"), a '^' segment sorts after the base version, numeric
// segments always outrank alpha segments, and separators are otherwise ignored.
func compareRPM(a, b string) int {
	ae, av, ar := splitEVR(a)
	be, bv, br := splitEVR(b)
	if c := compareNumeric(ae, be); c != 0 {
		return c
	}
	if c := rpmVerCmp(av, bv); c != 0 {
		return c
	}
	return rpmVerCmp(ar, br)
}

// splitEVR decomposes "[epoch:]version-release". A missing epoch defaults to
// "0"; a missing release to "".
func splitEVR(v string) (epoch, version, release string) {
	epoch = "0"
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if e := v[:i]; allDigits(e) {
			epoch = e
		}
		v = v[i+1:]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// rpmVerCmp is the segment-wise comparison at the heart of rpmvercmp.
func rpmVerCmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		// '~' sorts before everything else, including an absent segment.
		aTilde := i < len(a) && a[i] == '~'
		bTilde := j < len(b) && b[j] == '~'
		if aTilde || bTilde {
			if aTilde && bTilde {
				i++
				j++
				continue
			}
			if aTilde {
				return -1
			}
			return 1
		}
		// '^' sorts after the base (a version with a caret suffix is greater).
		aCaret := i < len(a) && a[i] == '^'
		bCaret := j < len(b) && b[j] == '^'
		if aCaret || bCaret {
			if aCaret && bCaret {
				i++
				j++
				continue
			}
			if aCaret {
				return 1
			}
			return -1
		}
		// Skip any run of separators (non-alphanumeric, non ~/^).
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		if a[i] == '~' || b[j] == '~' || a[i] == '^' || b[j] == '^' {
			continue
		}
		// Grab the next segment: either all-digit or all-alpha.
		aSeg, aIsNum := rpmSegment(a, &i)
		bSeg, bIsNum := rpmSegment(b, &j)
		if aIsNum != bIsNum {
			// A numeric segment always ranks above an alphabetic one.
			if aIsNum {
				return 1
			}
			return -1
		}
		if aIsNum {
			if c := compareNumeric(aSeg, bSeg); c != 0 {
				return c
			}
		} else if c := strings.Compare(aSeg, bSeg); c != 0 {
			return sign(c)
		}
	}
	// Whichever still has an alphanumeric/tilde/caret segment left decides.
	aRest := hasMoreRPM(a, i)
	bRest := hasMoreRPM(b, j)
	// A trailing '~' means the *longer* one is actually smaller.
	if aRest && i < len(a) && a[i] == '~' {
		return -1
	}
	if bRest && j < len(b) && b[j] == '~' {
		return 1
	}
	switch {
	case aRest && !bRest:
		return 1
	case !aRest && bRest:
		return -1
	default:
		return 0
	}
}

// rpmSegment reads a maximal run of digits or a maximal run of letters starting
// at *i, advancing *i past it, and reports whether the run was numeric.
func rpmSegment(s string, i *int) (string, bool) {
	start := *i
	if isDigit(s[*i]) {
		for *i < len(s) && isDigit(s[*i]) {
			*i++
		}
		return s[start:*i], true
	}
	for *i < len(s) && isAlpha(s[*i]) {
		*i++
	}
	return s[start:*i], false
}

// hasMoreRPM reports whether s[i:] still contains a meaningful (alphanumeric,
// tilde or caret) character.
func hasMoreRPM(s string, i int) bool {
	for ; i < len(s); i++ {
		if isAlnum(s[i]) || s[i] == '~' || s[i] == '^' {
			return true
		}
	}
	return false
}

func isAlnum(b byte) bool { return isDigit(b) || isAlpha(b) }
