// Package vuln is the engine module for vulnerability scanning (CAPABILITY_SPEC
// domain 2). It consumes the SBOM produced by internal/sbom — it never re-walks
// the image — matches each component against a local, offline advisory database
// (internal/vulndb), enriches matches with CVSS/EPSS/CISA-KEV, applies VEX
// statements and waivers to cut false positives, ranks by real exploitability,
// and projects the survivors into the unified Finding model.
//
// The design is "deterministic core, optional intelligence layer": matching and
// ranking are pure and reproducible with zero models or network present; the
// reachability-aware VEX auto-generation (reachability.go) is an off-by-default
// enrichment behind a clean interface. Given the same SBOM and the same pinned
// advisory DB, the findings are byte-identical — with one exception: DS-RAT-VULN-EOL
// falls back to the wall clock (time.Now().UTC()) when Options.Now is zero, so
// EOL findings are time-dependent unless a clock is explicitly injected via
// Options.Now. Pin Options.Now to get fully byte-identical output including EOL.
package vuln

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/sbom"
	"github.com/Ratnadeepdeyroy/docker-security/internal/vulndb"
)

const moduleName = "vuln"

// staleAfter is how old an advisory DB may be before the scan surfaces a
// staleness warning. It only fires when a clock is injected (Options.Now).
const staleAfter = 30 * 24 * time.Hour

// maxComponents bounds how many SBOM components the matcher will process, so a
// hostile image that inflates the SBOM into millions of entries cannot turn a
// scan into a denial of service. Beyond it, the module records a warning finding
// and stops rather than consuming unbounded memory.
const maxComponents = 200_000

// Options configures a vuln module. The zero value is valid: it uses the
// embedded advisory snapshot, no VEX/waivers, and reachability off (nothing is
// suppressed). Frontends may also pass configuration per-run via Target.Metadata
// (see optionsFromTarget), which is how the CLI/HTTP layers reach this module
// without a bespoke API.
type Options struct {
	// DB is the advisory source. When nil, the module loads DBPath if set,
	// otherwise the embedded bootstrap snapshot.
	DB     *vulndb.DB
	DBPath string

	// Now is the injected clock used for DB staleness and waiver expiry. Zero
	// disables both time-dependent behaviors, keeping analysis deterministic.
	Now time.Time

	// VEX holds OpenVEX statements that suppress not-affected/fixed findings.
	VEX []VEXStatement
	// Waivers are operator allowlist entries with a justification and expiry.
	Waivers []Waiver

	// Reachability, when set, judges whether a vulnerable symbol is plausibly
	// reached and can emit not_reachable VEX drafts. Nil means "always
	// reachable" — the safe default that suppresses nothing.
	Reachability Reachability
	// Symbols supplies per-component symbol evidence for reachability. Nil means
	// no evidence, so reachability never concludes not-reached (no false
	// negatives from a missing symbol table).
	Symbols SymbolSource
}

// Module is the vulnerability-scanning capability.
type Module struct {
	opts Options

	// dbCache memoizes loaded DBs keyed by DBPath ("" = the embedded bootstrap
	// snapshot). Keying by path (rather than a single sync.Once) means a
	// Module reused across Analyze calls with different Target.Metadata
	// ["vuln.db"] values — e.g. `dsecrat watch` re-invoking Analyze on the same
	// Module every cycle, or `dsecrat serve` fielding concurrent requests against
	// distinct advisory DBs — resolves each distinct DBPath correctly instead
	// of permanently pinning to whichever path the first call happened to use.
	//
	// dbMu guards only the map itself (find-or-create one *cachedDB entry per
	// key); the actual file I/O for a key happens outside dbMu, inside that
	// entry's own sync.Once. This is a per-key singleflight: two concurrent
	// Analyze calls for two different, both-uncached DBPaths load in parallel
	// instead of serializing behind one lock held for the whole read+parse;
	// two concurrent calls for the *same* uncached DBPath both wait on the
	// same Once and the file is read exactly once.
	dbMu    sync.Mutex
	dbCache map[string]*cachedDB
}

// cachedDB holds one resolveDB result (success or failure), loaded at most
// once via once regardless of how many goroutines request the same key
// concurrently, so a later call with the same DBPath never re-reads the file
// from disk.
type cachedDB struct {
	once sync.Once
	db   *vulndb.DB
	err  error
}

// New returns a vuln module using the embedded advisory snapshot and safe
// defaults (no suppression).
func New() *Module { return &Module{} }

// NewWithOptions returns a vuln module with explicit options, used by tests and
// by the frontends that pre-load a DB / VEX / waivers.
func NewWithOptions(o Options) *Module { return &Module{opts: o} }

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "Vulnerability scanning: match SBOM components against known CVEs (domain 2)"
}
func (m *Module) Domains() []string { return []string{"2"} }

// Supports mirrors the SBOM module: vulnerability matching applies to anything
// we can build an SBOM from.
func (m *Module) Supports(t engine.TargetType) bool {
	return t == engine.TargetImage || t == engine.TargetFilesystem
}

// Analyze generates the SBOM for the target, matches every component against the
// advisory DB, and returns the resulting findings plus a summary.
func (m *Module) Analyze(ctx context.Context, t *engine.Target) ([]engine.Finding, error) {
	opts := m.effectiveOptions(t)
	db, err := m.resolveDB(opts)
	if err != nil {
		return nil, err
	}

	doc, err := sbom.Generate(ctx, t)
	if err != nil {
		return nil, fmt.Errorf("vuln: build sbom: %w", err)
	}

	scan := newScanner(db, opts)
	findings, stats, err := scan.run(ctx, doc)
	if err != nil {
		// A scan canceled mid-match is not a successful (if partial) result:
		// propagate the cancellation rather than returning the partial
		// findings as if matching had completed cleanly.
		return nil, fmt.Errorf("vuln: scan canceled: %w", err)
	}

	if name, ver := doc.DistroNameVersion(); name != "" {
		now := opts.Now
		if now.IsZero() {
			now = time.Now().UTC()
		}
		if eolDate, eol, known := vulndb.DistroEOL(name, ver, now); known && eol {
			findings = append(findings, engine.Finding{
				RuleID:   "DS-RAT-VULN-EOL",
				Module:   moduleName,
				Severity: engine.SeverityHigh,
				Title:    fmt.Sprintf("Base distro %s %s is past end-of-life", name, ver),
				Description: fmt.Sprintf(
					"%s %s reached end-of-life on %s. No security advisories are published for it, so vulnerability scan results for OS packages are incomplete by definition.",
					name, ver, eolDate.Format("2006-01-02")),
				Resource:    doc.Source.Name,
				Remediation: "Rebuild on a supported base image release.",
				References:  []string{"NIST-SP-800-190"},
			})
		}
	}

	findings = append(findings, summaryFinding(db, doc, opts, stats))
	sortFindings(findings)
	return findings, nil
}

// effectiveOptions overlays per-run Target.Metadata configuration on top of the
// module's constructor options, so a frontend can point the module at a
// different DB or enable reachability without a new module type.
func (m *Module) effectiveOptions(t *engine.Target) Options {
	o := m.opts
	if t == nil || t.Metadata == nil {
		return o
	}
	if v := t.Metadata["vuln.db"]; v != "" {
		o.DBPath = v
	}
	if v := t.Metadata["vuln.now"]; v != "" && o.Now.IsZero() {
		if ts, err := time.Parse(time.RFC3339, v); err == nil {
			o.Now = ts
		}
	}
	return o
}

// resolveDB loads the advisory database and memoizes it per distinct DBPath
// ("" keys the embedded snapshot, so that fast path is still loaded only
// once). Precedence: an explicitly supplied DB, then a DBPath on disk, then
// the embedded snapshot. Caching by key (rather than a single sync.Once)
// means a later Analyze call on the same Module with a different DBPath
// reloads from the new path instead of silently reusing whatever was loaded
// first.
//
// The map lock (dbMu) is held only long enough to find-or-create the *cachedDB
// entry for key — never across the file I/O in vulndb.Open/Default. Loading
// happens inside that entry's own sync.Once, so:
//   - two concurrent calls with the same key block on the same Once and the
//     file is read exactly once;
//   - two concurrent calls with two different, both-uncached keys never wait
//     on each other — each blocks only on its own entry's Once.
func (m *Module) resolveDB(opts Options) (*vulndb.DB, error) {
	if opts.DB != nil {
		return opts.DB, nil
	}
	key := opts.DBPath

	m.dbMu.Lock()
	if m.dbCache == nil {
		m.dbCache = map[string]*cachedDB{}
	}
	c, ok := m.dbCache[key]
	if !ok {
		c = &cachedDB{}
		m.dbCache[key] = c
	}
	m.dbMu.Unlock()

	c.once.Do(func() {
		if key != "" {
			c.db, c.err = vulndb.Open(key)
		} else {
			c.db, c.err = vulndb.Default()
		}
	})
	if c.err != nil {
		return nil, fmt.Errorf("vuln: load advisory db: %w", c.err)
	}
	return c.db, nil
}

// --- Deterministic finding order ----------------------------------------

// sortFindings orders findings for a stable golden output: most severe first,
// then by the highest priority score, then by resource and rule id so identical
// runs are byte-identical regardless of map/scan iteration order.
func sortFindings(fs []engine.Finding) {
	sev := func(f engine.Finding) int { return int(f.Severity) }
	prio := func(f engine.Finding) string { return f.Metadata["priority_score"] }
	sort.SliceStable(fs, func(i, j int) bool {
		if sev(fs[i]) != sev(fs[j]) {
			return sev(fs[i]) > sev(fs[j])
		}
		if prio(fs[i]) != prio(fs[j]) {
			return prio(fs[i]) > prio(fs[j]) // lexical on zero-padded score
		}
		if fs[i].Resource != fs[j].Resource {
			return fs[i].Resource < fs[j].Resource
		}
		return fs[i].RuleID < fs[j].RuleID
	})
}
