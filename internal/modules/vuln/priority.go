package vuln

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/vulndb"
)

// --- Prioritization ------------------------------------------------------
//
// Ranking answers the question an operator or triage agent actually has: of the
// hundreds of CVEs in this image, which do I touch first? We fuse three signals
// the way modern practice recommends — CVSS severity for impact, CISA KEV for
// "is it being exploited right now", and EPSS for "how likely is it to be" —
// and discount matches judged unreachable. Every score ships with a rationale
// so the ranking is explainable, not a black box.

// priorityResult is the computed ranking plus its explanation.
type priorityResult struct {
	score       float64 // 0..~120, higher = act sooner
	label       string  // urgent | high | medium | low | deprioritized
	explanation string  // human sentence
	signals     string  // machine-readable "k=v;..." rationale
}

// Signal weights. KEV dominates because in-the-wild exploitation is the single
// strongest call to action; EPSS scales a meaningful but secondary contribution.
const (
	kevBoost   = 40.0
	epssWeight = 30.0
	// unreachableFactor discounts a match that reachability judged not-reached.
	unreachableFactor = 0.25
)

// computePriority fuses the signals into a deterministic score and rationale.
func computePriority(sev vulndb.Severity, kev bool, epss float64, haveEPSS bool, verdict Verdict) priorityResult {
	base := float64(sev.Rank()) * 10 // 0..50
	score := base

	reasons := []string{fmt.Sprintf("severity %s", severityWord(sev))}
	signals := []string{"severity=" + string(sev)}

	if kev {
		score += kevBoost
		reasons = append(reasons, "listed in CISA KEV (actively exploited)")
		signals = append(signals, "kev=true")
	} else {
		signals = append(signals, "kev=false")
	}
	if haveEPSS {
		score += epss * epssWeight
		reasons = append(reasons, fmt.Sprintf("EPSS %.1f%% exploit probability", epss*100))
		signals = append(signals, "epss="+strconv.FormatFloat(epss, 'f', 5, 64))
	}

	if !verdict.Reached {
		score *= unreachableFactor
		reasons = append(reasons, "deprioritized: vulnerable code not judged reachable")
		signals = append(signals, "reachable=false")
	} else if verdict.Reason != "" {
		signals = append(signals, "reachable=true")
	}

	label := priorityLabel(score, verdict.Reached)
	return priorityResult{
		score:       score,
		label:       label,
		explanation: fmt.Sprintf("Ranked %s (score %.1f): %s.", label, score, strings.Join(reasons, "; ")),
		signals:     strings.Join(signals, ";"),
	}
}

func priorityLabel(score float64, reached bool) string {
	if !reached {
		return "deprioritized"
	}
	switch {
	case score >= 70:
		return "urgent"
	case score >= 45:
		return "high"
	case score >= 25:
		return "medium"
	default:
		return "low"
	}
}

// formatScore renders the score zero-padded to a fixed width so lexical sorting
// of the metadata string matches numeric order, keeping the golden output
// stable and the CLI/JSON sort deterministic.
func formatScore(score float64) string {
	return fmt.Sprintf("%07.2f", score)
}

func severityWord(s vulndb.Severity) string {
	if s == vulndb.SevUnknown {
		return "unrated"
	}
	return string(s)
}
