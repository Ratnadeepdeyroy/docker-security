package vulndb

import (
	"math"
	"strings"
)

// --- CVSS v3.x base score ------------------------------------------------

// ParseCVSSVector parses a CVSS v3.0/3.1 vector string and returns the metric
// CVSS with its computed base score. ok is false for a vector that is not a
// recognizable v3 vector (v2/v4 vectors are returned verbatim with score 0 by
// the caller). Doing the arithmetic ourselves — rather than trusting a feed's
// self-reported number — means the score is reproducible and consistent across
// feeds that disagree.
func ParseCVSSVector(vector string) (CVSS, bool) {
	v := strings.TrimSpace(vector)
	if !strings.HasPrefix(v, "CVSS:3") {
		return CVSS{}, false
	}
	version := "3.1"
	m := map[string]string{}
	for _, part := range strings.Split(v, "/") {
		k, val, ok := strings.Cut(part, ":")
		if !ok {
			continue
		}
		if k == "CVSS" {
			version = val
			continue
		}
		m[k] = val
	}
	score, ok := cvss3BaseScore(m)
	if !ok {
		return CVSS{}, false
	}
	return CVSS{Version: version, Vector: v, Score: score}, true
}

// cvss3BaseScore applies the CVSS v3.1 base-score formula.
func cvss3BaseScore(m map[string]string) (float64, bool) {
	av, ok1 := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[m["AV"]]
	ac, ok2 := map[string]float64{"L": 0.77, "H": 0.44}[m["AC"]]
	ui, ok3 := map[string]float64{"N": 0.85, "R": 0.62}[m["UI"]]
	scope := m["S"]
	changed := scope == "C"
	prTable := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if changed {
		prTable = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	pr, ok4 := prTable[m["PR"]]
	impact := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}
	c, ok5 := impact[m["C"]]
	ii, ok6 := impact[m["I"]]
	a, ok7 := impact[m["A"]]
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) || (scope != "U" && scope != "C") {
		return 0, false
	}

	iscBase := 1 - (1-c)*(1-ii)*(1-a)
	var impactSub float64
	if changed {
		impactSub = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		impactSub = 6.42 * iscBase
	}
	if impactSub <= 0 {
		return 0, true
	}
	exploitability := 8.22 * av * ac * pr * ui
	raw := impactSub + exploitability
	if changed {
		raw *= 1.08
	}
	return roundUp1(math.Min(raw, 10)), true
}

// roundUp1 rounds up to one decimal place, as CVSS specifies (ceil to the next
// tenth, tolerating binary-float noise).
func roundUp1(x float64) float64 {
	return math.Ceil(x*10-1e-9) / 10
}

// SeverityFromScore maps a CVSS base score to the normalized qualitative band
// (CVSS v3 ranges).
func SeverityFromScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return SevCritical
	case score >= 7.0:
		return SevHigh
	case score >= 4.0:
		return SevMedium
	case score >= 0.1:
		return SevLow
	default:
		return SevNegligible
	}
}

// NormalizeSeverityWord maps assorted feed severity spellings to the normalized
// band, for feeds that report a word rather than a vector.
func NormalizeSeverityWord(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SevCritical
	case "high", "important":
		return SevHigh
	case "medium", "moderate":
		return SevMedium
	case "low", "minor":
		return SevLow
	case "negligible", "none":
		return SevNegligible
	default:
		return SevUnknown
	}
}
