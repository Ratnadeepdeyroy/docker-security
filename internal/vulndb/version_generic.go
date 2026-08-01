package vulndb

import "strings"

// --- Generic fallback comparison ----------------------------------------

// compareGeneric compares two version strings with no ecosystem-specific rules:
// it splits both into numeric and alphabetic tokens (on any punctuation and on
// digit↔letter boundaries) and compares token by token, with numeric tokens
// ordered by magnitude and ranking above alphabetic tokens. It never panics on
// odd input — the worst case degrades to a byte comparison — so an ecosystem we
// do not yet model still yields a total, deterministic order.
func compareGeneric(a, b string) int {
	ta := genericTokens(a)
	tb := genericTokens(b)
	n := len(ta)
	if len(tb) > n {
		n = len(tb)
	}
	for i := 0; i < n; i++ {
		if i >= len(ta) {
			return -1 // a is a prefix of b ⇒ smaller
		}
		if i >= len(tb) {
			return 1
		}
		x, y := ta[i], tb[i]
		xNum, yNum := allDigits(x), allDigits(y)
		switch {
		case xNum && yNum:
			if c := compareNumeric(x, y); c != 0 {
				return c
			}
		case xNum: // numeric ranks above alphabetic
			return 1
		case yNum:
			return -1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return sign(c)
			}
		}
	}
	return 0
}

// genericTokens splits on punctuation and on digit↔letter transitions.
func genericTokens(v string) []string {
	var out []string
	var cur strings.Builder
	lastDigit := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case isAlnum(c):
			if cur.Len() > 0 && isDigit(c) != lastDigit {
				flush()
			}
			cur.WriteByte(c)
			lastDigit = isDigit(c)
		default:
			flush()
		}
	}
	flush()
	return out
}
