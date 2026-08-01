package vuln

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/sbom"
	"github.com/Ratnadeepdeyroy/docker-security/internal/vulndb"
)

// --- Scan summary --------------------------------------------------------

// summaryFinding emits a single INFO finding describing the run: how many
// components were scanned, how many advisories the DB holds, its age/staleness,
// and how many matches were suppressed by VEX/waivers or flagged unreachable.
// It is gating-neutral (INFO) and gives an operator — or an agent — the context
// to trust the numbers.
func summaryFinding(db *vulndb.DB, doc *sbom.SBOM, opts Options, st stats) engine.Finding {
	md := map[string]string{
		"components_scanned": strconv.Itoa(st.components),
		"advisories_in_db":   strconv.Itoa(db.Count()),
		"matches":            strconv.Itoa(st.matched),
		"reported":           strconv.Itoa(st.matched - st.vexSuppressed - st.waived),
		"vex_suppressed":     strconv.Itoa(st.vexSuppressed),
		"waived":             strconv.Itoa(st.waived),
		"not_reachable":      strconv.Itoa(st.notReachable),
		"kev_hits":           strconv.Itoa(st.kev),
		"db_built_at":        db.BuiltAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	if doc.Source.Distro != "" {
		md["distro"] = doc.Source.Distro
	}

	var notes []string
	// Staleness only when a clock is injected, so tests stay deterministic.
	if !opts.Now.IsZero() && !db.BuiltAt.IsZero() {
		days := int(db.Age(opts.Now).Hours() / 24)
		md["db_age_days"] = strconv.Itoa(days)
		if db.Stale(opts.Now, staleAfter) {
			md["db_stale"] = "true"
			notes = append(notes, fmt.Sprintf("advisory DB is %d days old; run `dsecrat db update`", days))
		}
	}
	if st.truncated {
		md["truncated"] = "true"
		notes = append(notes, fmt.Sprintf("SBOM exceeded %d components; matching was truncated", maxComponents))
	}

	desc := fmt.Sprintf("Scanned %d components against %d advisories: %d reported, %d suppressed by VEX, %d waived, %d flagged not-reachable.",
		st.components, db.Count(), st.matched-st.vexSuppressed-st.waived, st.vexSuppressed, st.waived, st.notReachable)
	if len(notes) > 0 {
		desc += " " + strings.Join(notes, "; ") + "."
	}

	return engine.Finding{
		RuleID:      "DS-RAT-VULN-000",
		Module:      moduleName,
		Severity:    engine.SeverityInfo,
		Title:       fmt.Sprintf("Vulnerability scan: %d finding(s) across %d components", st.matched-st.vexSuppressed-st.waived, st.components),
		Description: desc,
		Resource:    doc.Source.Name,
		References:  []string{"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
		Metadata:    md,
	}
}
