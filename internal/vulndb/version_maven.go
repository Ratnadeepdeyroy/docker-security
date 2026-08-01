package vulndb

import "strings"

// --- Maven version comparison -------------------------------------------

// mavenQualifiers is Maven's well-known qualifier ordering. Everything to the
// left of the empty string is a pre-release; "sp" (service pack) is a
// post-release. An unknown qualifier sorts *after* all of these and lexically
// among its peers.
var mavenQualifiers = map[string]int{
	"alpha": 0, "beta": 1, "milestone": 2, "rc": 3, "snapshot": 4,
	"":   5, // the release itself
	"sp": 6,
}

const mavenUnknownRank = 7

// mavenItem is one token of a Maven version: a numeric run or a qualifier.
type mavenItem struct {
	isNum bool
	num   string
	qual  string
}

// compareMaven compares two Maven versions following the ordering that Maven's
// ComparableVersion defines: numeric and qualifier tokens interleave, a numeric
// token outranks a qualifier at the same position, and qualifiers follow the
// well-known pre-release/release/post-release order. This is why
// "1.0-alpha" < "1.0-SNAPSHOT" < "1.0" < "1.0-sp" < "1.0-foo".
func compareMaven(a, b string) int {
	ia := tokenizeMaven(a)
	ib := tokenizeMaven(b)
	n := len(ia)
	if len(ib) > n {
		n = len(ib)
	}
	for i := 0; i < n; i++ {
		var x, y *mavenItem
		if i < len(ia) {
			x = &ia[i]
		}
		if i < len(ib) {
			y = &ib[i]
		}
		if c := compareMavenItem(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// compareMavenItem compares two tokens, substituting an absent token with the
// neutral element appropriate to its counterpart: a missing numeric token is
// "0", a missing qualifier is the release ("").
func compareMavenItem(x, y *mavenItem) int {
	if x == nil && y == nil {
		return 0
	}
	if x == nil {
		x = neutralLike(y)
	}
	if y == nil {
		y = neutralLike(x)
	}
	switch {
	case x.isNum && y.isNum:
		return compareNumeric(x.num, y.num)
	case x.isNum: // numeric outranks qualifier
		return 1
	case y.isNum:
		return -1
	default:
		return compareMavenQual(x.qual, y.qual)
	}
}

func neutralLike(other *mavenItem) *mavenItem {
	if other.isNum {
		return &mavenItem{isNum: true, num: "0"}
	}
	return &mavenItem{qual: ""}
}

func compareMavenQual(a, b string) int {
	ra, unknownA := mavenQualifiers[a]
	rb, unknownB := mavenQualifiers[b]
	knownA, knownB := unknownA, unknownB
	if !knownA {
		ra = mavenUnknownRank
	}
	if !knownB {
		rb = mavenUnknownRank
	}
	if ra != rb {
		return sign(ra - rb)
	}
	if !knownA && !knownB {
		return sign(strings.Compare(a, b)) // both unknown: lexical
	}
	return 0
}

// tokenizeMaven splits a version into numeric/qualifier tokens, breaking on the
// separators '.', '-', '_' and on every digit↔letter boundary, then normalizes
// qualifier aliases (a→alpha, cr→rc, ga/final/release→"").
func tokenizeMaven(v string) []mavenItem {
	v = strings.ToLower(strings.TrimSpace(v))
	var raw []string
	var cur strings.Builder
	lastDigit := false
	flush := func() {
		if cur.Len() > 0 {
			raw = append(raw, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '.' || c == '-' || c == '_' || c == '+':
			flush()
		case isDigit(c):
			if cur.Len() > 0 && !lastDigit {
				flush()
			}
			cur.WriteByte(c)
			lastDigit = true
		default:
			if cur.Len() > 0 && lastDigit {
				flush()
			}
			cur.WriteByte(c)
			lastDigit = false
		}
	}
	flush()

	out := make([]mavenItem, 0, len(raw))
	for _, tok := range raw {
		if allDigits(tok) {
			out = append(out, mavenItem{isNum: true, num: tok})
			continue
		}
		out = append(out, mavenItem{qual: normalizeMavenQual(tok)})
	}
	return out
}

func normalizeMavenQual(q string) string {
	switch q {
	case "a":
		return "alpha"
	case "b":
		return "beta"
	case "m":
		return "milestone"
	case "cr":
		return "rc"
	case "ga", "final", "release":
		return ""
	default:
		return q
	}
}
