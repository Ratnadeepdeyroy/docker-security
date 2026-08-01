package vulndb

import (
	"strconv"
	"strings"
)

// --- Python PEP 440 version comparison ----------------------------------

// pep440 is a parsed PEP 440 version. Local versions (after '+') are kept only
// as a presence flag: they order after the same public version, but their
// internal ordering rarely matters for advisory matching.
type pep440 struct {
	epoch   int
	release []int
	preKind int // dev/a/b/rc ordered below the release; preNone otherwise
	preNum  int
	hasPost bool
	postNum int
	hasDev  bool
	devNum  int
}

// Pre-release ordering weights: dev < alpha < beta < rc < (release).
const (
	preA    = 1
	preB    = 2
	preRC   = 3
	preNone = 4
)

// comparePEP440 compares two Python versions per PEP 440: epoch, then release
// segments, then a phase ordering where .devN precedes a pre-release, which
// precedes the final release, which precedes .postN. This ordering is why
// "1.0rc1" < "1.0" < "1.0.post1" — a distinction plain semver gets wrong.
func comparePEP440(a, b string) int {
	pa := parsePEP440(a)
	pb := parsePEP440(b)
	if pa.epoch != pb.epoch {
		return sign(pa.epoch - pb.epoch)
	}
	if c := compareIntSlices(pa.release, pb.release); c != 0 {
		return c
	}
	if c := sign(pep440Phase(pa) - pep440Phase(pb)); c != 0 {
		return c
	}
	// Within the same pre-release kind, compare the pre-release number.
	if pa.preKind != preNone && pa.preKind == pb.preKind {
		if c := sign(pa.preNum - pb.preNum); c != 0 {
			return c
		}
	}
	if c := comparePresenceNum(pa.hasPost, pa.postNum, pb.hasPost, pb.postNum, false); c != 0 {
		return c
	}
	// A .devN sorts BELOW the same version without it, so "absent dev" is the
	// higher of the two.
	return comparePresenceNum(pa.hasDev, pa.devNum, pb.hasDev, pb.devNum, true)
}

// comparePresenceNum compares an optional numeric segment. When absentIsHigher
// is true, a present value sorts below an absent one (the .devN rule); when
// false, a present value sorts above an absent one (the .postN rule).
func comparePresenceNum(aHas bool, aNum int, bHas bool, bNum int, absentIsHigher bool) int {
	if aHas && bHas {
		return sign(aNum - bNum)
	}
	if !aHas && !bHas {
		return 0
	}
	// Exactly one present.
	present := aHas
	if absentIsHigher {
		if present {
			return -1
		}
		return 1
	}
	if present {
		return 1
	}
	return -1
}

// pep440Phase buckets dev/pre/release into a monotone order so cross-phase
// comparison is a simple integer compare (the common case).
func pep440Phase(p pep440) int {
	switch {
	case p.hasDev && p.preKind == preNone:
		return 0 // pure .devN, below any pre-release
	case p.preKind != preNone:
		return 1 + p.preKind // a/b/rc buckets 2..4
	default:
		return 5 // the release (post is handled by the postNum comparison)
	}
}

func parsePEP440(v string) pep440 {
	p := pep440{preKind: preNone}
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i] // drop local version segment
	}
	if i := strings.IndexByte(v, '!'); i >= 0 {
		p.epoch = atoiSafe(v[:i])
		v = v[i+1:]
	}
	// Normalize separators so ".dev", "-dev", "_dev", "dev" all parse alike.
	v = strings.NewReplacer("-", ".", "_", ".").Replace(v)

	if i := strings.Index(v, "dev"); i >= 0 {
		p.hasDev = true
		p.devNum = trailingNum(v[i+3:])
		v = strings.TrimRight(v[:i], ".")
	}
	for _, kw := range []string{"post", "rev"} {
		if i := strings.Index(v, kw); i >= 0 {
			p.hasPost = true
			p.postNum = trailingNum(v[i+len(kw):])
			v = strings.TrimRight(v[:i], ".")
			break
		}
	}
	for _, pr := range []struct {
		kw   string
		kind int
	}{{"alpha", preA}, {"beta", preB}, {"preview", preRC}, {"pre", preRC}, {"rc", preRC}, {"c", preRC}, {"a", preA}, {"b", preB}} {
		if i := strings.Index(v, pr.kw); i >= 0 && preBoundary(v, i) {
			p.preKind = pr.kind
			p.preNum = trailingNum(v[i+len(pr.kw):])
			v = strings.TrimRight(v[:i], ".")
			break
		}
	}
	for _, seg := range strings.Split(v, ".") {
		if seg != "" {
			p.release = append(p.release, atoiSafe(seg))
		}
	}
	return p
}

// preBoundary ensures a pre-release keyword sits on a digit/separator boundary,
// so "beta" in "1.0beta" is recognized while a stray mid-token letter is not.
func preBoundary(v string, i int) bool {
	if i == 0 {
		return true
	}
	c := v[i-1]
	return isDigit(c) || c == '.'
}

func compareIntSlices(a, b []int) int {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(a) {
			av = a[i]
		}
		if i < len(b) {
			bv = b[i]
		}
		if av != bv {
			return sign(av - bv)
		}
	}
	return 0
}

// trailingNum reads a leading integer from s (after separators), defaulting to
// 0 when the segment carries no number (e.g. a bare "rc").
func trailingNum(s string) int {
	s = strings.TrimLeft(s, ".")
	end := 0
	for end < len(s) && isDigit(s[end]) {
		end++
	}
	if end == 0 {
		return 0
	}
	return atoiSafe(s[:end])
}

func atoiSafe(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
