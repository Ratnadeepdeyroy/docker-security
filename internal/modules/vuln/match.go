package vuln

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/sbom"
	"github.com/Ratnadeepdeyroy/docker-security/internal/vulndb"
)

// --- Matching engine -----------------------------------------------------

// scanner holds the resolved dependencies for one Analyze pass.
type scanner struct {
	db      *vulndb.DB
	opts    Options
	reach   Reachability
	symbols SymbolSource
}

// stats accumulates counts for the run summary.
type stats struct {
	components    int
	matched       int
	vexSuppressed int
	waived        int
	notReachable  int
	kev           int
	truncated     bool
}

func newScanner(db *vulndb.DB, opts Options) *scanner {
	reach := opts.Reachability
	if reach == nil {
		reach = alwaysReached{} // off by default: nothing is judged unreachable
	}
	return &scanner{db: db, opts: opts, reach: reach, symbols: opts.Symbols}
}

// run matches every component in the SBOM and returns the projected findings.
//
// If ctx is canceled mid-scan, run stops early and returns ctx.Err() alongside
// whatever partial findings/stats it had accumulated. A canceled scan is not a
// successful one: the caller (Analyze) must not present the partial result as
// if matching had genuinely completed, so it propagates this error rather than
// swallowing it. This is distinct from the maxComponents guard below, which is
// an intentional, successful truncation flagged via st.truncated rather than
// an error.
func (s *scanner) run(ctx context.Context, doc *sbom.SBOM) ([]engine.Finding, stats, error) {
	var (
		out  []engine.Finding
		st   stats
		seen = map[string]bool{} // component-identity|advisory-id → deduped
	)
	distroID := distroIDOf(doc)

	for _, comp := range doc.Components {
		if err := ctx.Err(); err != nil {
			return out, st, err
		}
		st.components++
		if st.components > maxComponents {
			st.truncated = true
			break
		}
		coord, ok := coordFor(comp, distroID)
		if !ok {
			continue
		}
		for _, i := range s.db.IndicesFor(coord) {
			adv := s.db.At(i)
			if !vulndb.Vulnerable(coord.Scheme, coord.Version, adv.Ranges) {
				continue
			}
			dedup := componentIdentity(comp) + "|" + adv.ID
			if seen[dedup] {
				continue
			}
			seen[dedup] = true
			st.matched++

			f, disp := s.project(comp, coord, *adv)
			switch disp {
			case dispSuppressedVEX:
				st.vexSuppressed++
				continue
			case dispWaived:
				st.waived++
				continue
			case dispNotReachable:
				st.notReachable++
			}
			if f.Metadata["kev"] == "true" {
				st.kev++
			}
			out = append(out, f)
		}
	}
	return out, st, nil
}

// disposition is the outcome of applying suppression policy to a match.
type disposition int

const (
	dispReport disposition = iota
	dispSuppressedVEX
	dispWaived
	dispNotReachable // still reported, but flagged/deprioritized
)

// project builds the enriched Finding for a component/advisory match and decides
// how policy (VEX, waivers, reachability) affects it.
func (s *scanner) project(comp sbom.Component, coord vulndb.Coord, adv vulndb.Advisory) (engine.Finding, disposition) {
	ids := advisoryIDs(adv)

	// VEX first: an explicit not_affected/fixed statement means "don't report".
	if st, _, ok := matchVEX(s.opts.VEX, ids, comp.PURL); ok && (st == vexNotAffected || st == vexFixed) {
		return engine.Finding{}, dispSuppressedVEX
	}
	// Waivers: an active (unexpired) allowlist entry suppresses with an audit reason.
	if _, ok := matchWaiver(s.opts.Waivers, ids, coord.Package, s.opts.Now); ok {
		return engine.Finding{}, dispWaived
	}

	kev := s.db.IsKEV(ids)
	epss, haveEPSS := s.db.EPSSFor(ids)
	fixed := adv.FixedVersion(coord.Scheme)

	// Reachability (off by default). A not-reached verdict does not suppress —
	// it annotates and deprioritizes, and yields an OpenVEX draft for sign-off.
	used, haveSyms := s.symbolsFor(comp)
	verdict := s.reach.Reached(Evidence{Component: comp, Coord: coord, UsedSymbols: used, HaveSymbols: haveSyms}, adv)

	pr := computePriority(adv.Severity, kev, epss, haveEPSS, verdict)

	f := engine.Finding{
		RuleID:      ruleID(adv),
		Module:      moduleName,
		Severity:    engineSeverity(adv.Severity, kev),
		Title:       title(adv, coord),
		Description: description(adv, coord, fixed),
		Resource:    resourceOf(comp, coord),
		Location:    locationOf(comp),
		Remediation: remediationText(coord, fixed),
		References:  references(adv),
		Metadata:    map[string]string{},
	}

	md := f.Metadata
	md["vulnerability"] = adv.ID
	if len(adv.Aliases) > 0 {
		md["aliases"] = strings.Join(adv.Aliases, ",")
	}
	md["ecosystem"] = string(coord.Ecosystem)
	md["package"] = coord.Package
	md["installed_version"] = coord.Version
	md["fix_state"] = fixState(fixed)
	if fixed != "" {
		md["fixed_version"] = fixed
	}
	md["severity"] = string(adv.Severity)
	if adv.CVSS != nil {
		md["cvss_score"] = strconv.FormatFloat(adv.CVSS.Score, 'f', 1, 64)
		md["cvss_vector"] = adv.CVSS.Vector
	}
	if haveEPSS {
		md["epss"] = strconv.FormatFloat(epss, 'f', 5, 64)
	}
	md["kev"] = strconv.FormatBool(kev)
	if len(adv.CWEs) > 0 {
		md["cwes"] = strings.Join(adv.CWEs, ",")
	}

	// Priority signals — the machine+human rationale an agent triaging 500 CVEs
	// can act on rather than just list.
	md["priority"] = pr.label
	md["priority_score"] = formatScore(pr.score)
	md["priority_explanation"] = pr.explanation
	md["priority_signals"] = pr.signals

	// Structured, agent-consumable remediation.
	md["fix"] = encodeFix(structuredFix(coord, fixed))

	disp := dispReport
	if !verdict.Reached {
		disp = dispNotReachable
		md["reachable"] = "false"
		md["reachability_reason"] = verdict.Reason
		md["vex_draft"] = generateVEXDraft(adv, comp, verdict)
	} else if haveSyms {
		md["reachable"] = "true"
		md["reachability_reason"] = verdict.Reason
	}

	return f, disp
}

// symbolsFor returns the symbol evidence for a component, or (nil,false) when no
// symbol source is configured — the safe state in which reachability concludes
// nothing.
func (s *scanner) symbolsFor(c sbom.Component) (map[string]bool, bool) {
	if s.symbols == nil {
		return nil, false
	}
	return s.symbols.Symbols(c)
}

// --- Coordinate derivation ----------------------------------------------

// coordFor derives the advisory lookup coordinate for a component, preferring
// its PURL and falling back to the cataloger name so components recorded without
// a PURL still get matched.
func coordFor(c sbom.Component, distroID string) (vulndb.Coord, bool) {
	if c.PURL != "" {
		if coord, ok := vulndb.ParsePURL(c.PURL); ok {
			if coord.Version == "" {
				coord.Version = c.Version
			}
			return coord, true
		}
	}
	return vulndb.FromCataloger(c.FoundBy, c.Name, c.Version, distroID)
}

func distroIDOf(doc *sbom.SBOM) string {
	// Source.Distro is like "alpine 3.19.1"; the id is the first field.
	if doc == nil {
		return ""
	}
	if i := strings.IndexByte(doc.Source.Distro, ' '); i >= 0 {
		return doc.Source.Distro[:i]
	}
	return doc.Source.Distro
}

// componentIdentity is a stable key for de-duplicating matches on the same
// physical package.
func componentIdentity(c sbom.Component) string {
	if c.PURL != "" {
		return c.PURL
	}
	return string(c.Type) + "|" + c.Name + "@" + c.Version
}

// advisoryIDs returns the advisory's primary id plus its aliases — the set of
// identifiers to test against KEV/EPSS tables, VEX statements, and waivers.
func advisoryIDs(adv vulndb.Advisory) []string {
	out := make([]string, 0, len(adv.Aliases)+1)
	if adv.ID != "" {
		out = append(out, adv.ID)
	}
	out = append(out, adv.Aliases...)
	return out
}

// --- Finding field builders ---------------------------------------------

// ruleID namespaces every vulnerability finding under DS-RAT-VULN- while preserving
// the CVE/advisory identity, so SARIF consumers still group per-CVE and the
// finding keeps a stable, area-prefixed rule id.
func ruleID(adv vulndb.Advisory) string { return "DS-RAT-VULN-" + adv.ID }

func title(adv vulndb.Advisory, coord vulndb.Coord) string {
	return fmt.Sprintf("%s in %s %s (%s)", adv.ID, coord.Package, displayVersion(coord.Version), coord.Ecosystem)
}

func description(adv vulndb.Advisory, coord vulndb.Coord, fixed string) string {
	var b strings.Builder
	if adv.Summary != "" {
		b.WriteString(adv.Summary)
	} else {
		fmt.Fprintf(&b, "%s affects %s.", adv.ID, coord.Package)
	}
	if fixed != "" {
		fmt.Fprintf(&b, " Fixed in %s.", fixed)
	} else {
		b.WriteString(" No fixed version is available yet.")
	}
	return b.String()
}

func resourceOf(c sbom.Component, coord vulndb.Coord) string {
	if c.PURL != "" {
		return c.PURL
	}
	return string(coord.Ecosystem) + ":" + coord.Package + "@" + coord.Version
}

func locationOf(c sbom.Component) *engine.Location {
	if c.Source == "" {
		return nil
	}
	return &engine.Location{Path: c.Source}
}

func remediationText(coord vulndb.Coord, fixed string) string {
	if fixed == "" {
		return fmt.Sprintf("No fixed version is published for %s yet; track the advisory and consider removing or isolating the package.", coord.Package)
	}
	return fmt.Sprintf("Upgrade %s from %s to %s or later.", coord.Package, displayVersion(coord.Version), fixed)
}

func references(adv vulndb.Advisory) []string {
	refs := append([]string(nil), adv.References...)
	// Ensure an NVD link exists for CVEs even when a feed omitted references.
	if strings.HasPrefix(strings.ToUpper(adv.ID), "CVE-") {
		nvd := "https://nvd.nist.gov/vuln/detail/" + adv.ID
		if !containsString(refs, nvd) {
			refs = append(refs, nvd)
		}
	}
	return refs
}

// engineSeverity maps a normalized advisory severity to the engine scale.
// A KEV-listed vulnerability is escalated to at least HIGH: in-the-wild
// exploitation outranks a modest CVSS band for gating purposes.
func engineSeverity(s vulndb.Severity, kev bool) engine.Severity {
	base := engine.SeverityUnknown
	switch s {
	case vulndb.SevCritical:
		base = engine.SeverityCritical
	case vulndb.SevHigh:
		base = engine.SeverityHigh
	case vulndb.SevMedium:
		base = engine.SeverityMedium
	case vulndb.SevLow:
		base = engine.SeverityLow
	case vulndb.SevNegligible:
		base = engine.SeverityInfo
	}
	if kev && base < engine.SeverityHigh {
		return engine.SeverityHigh
	}
	return base
}

func fixState(fixed string) string {
	if fixed == "" {
		return "not-fixed"
	}
	return "fixed"
}

func displayVersion(v string) string {
	if v == "" {
		return "(unknown version)"
	}
	return v
}

func containsString(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
