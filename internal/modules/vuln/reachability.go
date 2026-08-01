package vuln

import (
	"encoding/json"

	"github.com/Ratnadeepdeyroy/docker-security/internal/sbom"
	"github.com/Ratnadeepdeyroy/docker-security/internal/vulndb"
)

// --- Reachability-aware VEX auto-generation (AI-age feature) -------------
//
// The CVE flood is mostly noise: a package can be present without its vulnerable
// code ever being called. Reachability turns that flood into a short list. The
// core is a deterministic, symbol-level heuristic (the same idea as
// govulncheck): an advisory that names its vulnerable symbols is only "reached"
// when one of those symbols is actually used by the artifact. When it is not,
// we emit an OpenVEX `not_reachable` DRAFT for a human — or an AI agent — to
// review and sign, rather than silently dropping the finding.
//
// It is off by default (the default analyzer judges everything reachable, so
// nothing is suppressed or deprioritized) and it is *conservative*: without
// symbol evidence, or for an advisory that does not declare its symbols, it
// never concludes not-reached — so it can only ever cut confirmed noise, never
// hide a real risk. A model-assisted reasoning layer can implement the same
// Reachability interface to refine verdicts without touching the core.

// Verdict is a reachability judgement for one component/advisory pair.
type Verdict struct {
	Reached    bool
	Reason     string
	Confidence string // "high" | "medium" | "low"
}

// Evidence is what an analyzer gets to reason over.
type Evidence struct {
	Component   sbom.Component
	Coord       vulndb.Coord
	UsedSymbols map[string]bool // symbols/imports observed in the artifact
	HaveSymbols bool            // whether symbol evidence was available at all
}

// Reachability judges whether a vulnerability's code is plausibly reached.
type Reachability interface {
	Reached(ev Evidence, adv vulndb.Advisory) Verdict
}

// SymbolSource supplies per-component symbol evidence to the reachability layer.
// A real implementation reads symbol tables from binaries or import graphs from
// lockfiles; the module ships without one, so reachability stays inert until a
// caller wires evidence in.
type SymbolSource interface {
	// Symbols returns the set of symbols/imports observed for a component and
	// whether any symbol information was available.
	Symbols(c sbom.Component) (used map[string]bool, have bool)
}

// alwaysReached is the default analyzer: it treats every match as reachable, so
// with reachability unconfigured nothing is deprioritized or drafted.
type alwaysReached struct{}

func (alwaysReached) Reached(Evidence, vulndb.Advisory) Verdict {
	return Verdict{Reached: true, Reason: "reachability analysis disabled", Confidence: "low"}
}

// SymbolReachability is the deterministic heuristic analyzer. Enable it (with a
// SymbolSource) to cut confirmed noise.
type SymbolReachability struct{}

// Reached applies the symbol-level rule:
//   - advisory declares no symbols            → reachable (unknown, be safe)
//   - no symbol evidence for the component     → reachable (be safe)
//   - evidence present, none of the advisory's symbols used → NOT reached
//   - otherwise (an affected symbol is used)   → reachable
func (SymbolReachability) Reached(ev Evidence, adv vulndb.Advisory) Verdict {
	if len(adv.Symbols) == 0 {
		return Verdict{Reached: true, Reason: "advisory does not identify vulnerable symbols", Confidence: "low"}
	}
	if !ev.HaveSymbols {
		return Verdict{Reached: true, Reason: "no symbol evidence available for component", Confidence: "low"}
	}
	for _, sym := range adv.Symbols {
		if ev.UsedSymbols[sym] {
			return Verdict{Reached: true, Reason: "vulnerable symbol " + sym + " is used", Confidence: "high"}
		}
	}
	return Verdict{Reached: false, Reason: "none of the vulnerable symbols are used by the artifact", Confidence: "high"}
}

// MapSymbolSource is a trivial SymbolSource backed by an in-memory map, keyed by
// component PURL (falling back to name). It exists so callers and tests can
// inject symbol evidence without a binary analyzer.
type MapSymbolSource map[string][]string

func (m MapSymbolSource) Symbols(c sbom.Component) (map[string]bool, bool) {
	key := c.PURL
	syms, ok := m[key]
	if !ok {
		syms, ok = m[c.Name]
	}
	if !ok {
		return nil, false
	}
	set := make(map[string]bool, len(syms))
	for _, s := range syms {
		set[s] = true
	}
	return set, true
}

// generateVEXDraft renders an OpenVEX `not_affected` statement (justification
// vulnerable_code_not_in_execute_path) for a match judged unreachable. It is a
// DRAFT: unsigned, off the suppression path, attached to the finding for a human
// or agent to review and adopt.
func generateVEXDraft(adv vulndb.Advisory, comp sbom.Component, verdict Verdict) string {
	stmt := map[string]any{
		"vulnerability":    map[string]string{"name": adv.ID},
		"products":         []string{comp.PURL},
		"status":           string(vexNotAffected),
		"justification":    "vulnerable_code_not_in_execute_path",
		"impact_statement": verdict.Reason,
	}
	doc := map[string]any{
		"@context":   "https://openvex.dev/ns/v0.2.0",
		"draft":      true,
		"statements": []any{stmt},
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return ""
	}
	return string(data)
}
