package vulndb

import "strings"

// --- Version comparison (dispatch) --------------------------------------

// Compare returns -1, 0, or +1 as version a is less than, equal to, or greater
// than b, using the ordering rules of the given scheme. Comparison is total and
// deterministic; unparseable input degrades to a byte-wise comparison rather
// than panicking, so hostile version strings can never crash a scan.
func Compare(sch VersionScheme, a, b string) int {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == b {
		return 0
	}
	switch sch {
	case SchemeDeb:
		return compareDeb(a, b)
	case SchemeRPM:
		return compareRPM(a, b)
	case SchemeAPK:
		return compareAPK(a, b)
	case SchemePEP440:
		return comparePEP440(a, b)
	case SchemeGo:
		return compareGo(a, b)
	case SchemeMaven:
		return compareMaven(a, b)
	case SchemeSemver, SchemeGem:
		return compareSemver(a, b)
	default:
		return compareGeneric(a, b)
	}
}

// --- shared low-level helpers -------------------------------------------

// sign clamps an integer difference to the {-1,0,1} contract of Compare.
func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// compareNumeric compares two all-digit strings by magnitude, tolerating
// leading zeros and arbitrary length (no integer overflow). Empty is treated
// as zero.
func compareNumeric(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	return sign(strings.Compare(a, b))
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
func isAlpha(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }
