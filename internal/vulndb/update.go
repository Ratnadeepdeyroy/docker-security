package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// --- Database update / feed normalization -------------------------------

// Options configures a database rebuild. The rebuild is offline by default: it
// reads raw feed documents from FromDir. Network access is opt-in and provided
// by a Fetcher (net/http lives behind that interface so tests never touch the
// wire). Now is injected so the build timestamp is deterministic in tests.
type Options struct {
	FromDir string             // directory of OSV JSON documents (+ optional epss.json/kev.json)
	Fetcher Fetcher            // optional network source; nil = air-gapped
	Now     time.Time          // build timestamp
	Source  string             // human label recorded in the DB
	EPSS    map[string]float64 // enrichment overlay (merged over any epss.json)
	KEV     []string           // enrichment overlay (merged over any kev.json)
}

// Fetcher retrieves raw OSV record documents from a remote source. Each returned
// element is one OSV JSON document.
type Fetcher interface {
	Fetch(ctx context.Context) ([][]byte, error)
}

// Update rebuilds an advisory DB from the configured sources, normalizing every
// feed into the internal schema and de-duplicating by alias. It is safe to run
// air-gapped (Fetcher nil) against a committed snapshot directory.
func Update(ctx context.Context, opts Options) (*DB, error) {
	var docs [][]byte

	if opts.FromDir != "" {
		fromDir, err := readOSVDir(opts.FromDir)
		if err != nil {
			return nil, err
		}
		docs = append(docs, fromDir...)
	}
	if opts.Fetcher != nil {
		remote, err := opts.Fetcher.Fetch(ctx)
		if err != nil {
			return nil, fmt.Errorf("vuln update: fetch: %w", err)
		}
		docs = append(docs, remote...)
	}

	var advisories []Advisory
	var skipped int
	for _, doc := range docs {
		adv, err := normalizeOSV(doc)
		if err != nil {
			// Skip an unparseable record rather than failing the whole update;
			// a single malformed feed entry must not poison the database. But
			// count it: a feed that's silently mostly-broken should be visible
			// to whoever runs the update, not indistinguishable from a clean
			// rebuild (see DB.SkippedRecords).
			skipped++
			continue
		}
		advisories = append(advisories, adv...)
	}
	advisories = mergeByAlias(advisories)

	db := &DB{
		Schema:         currentSchema,
		BuiltAt:        opts.Now.UTC(),
		Source:         opts.Source,
		Advisories:     advisories,
		EPSS:           map[string]float64{},
		KEV:            nil,
		SkippedRecords: skipped,
	}
	// Enrichment overlays: epss.json/kev.json in FromDir, then explicit Options.
	if opts.FromDir != "" {
		loadEnrichment(opts.FromDir, db)
	}
	for k, v := range opts.EPSS {
		db.EPSS[strings.ToUpper(k)] = v
	}
	db.KEV = dedupUpper(append(db.KEV, opts.KEV...))
	db.index()
	return db, nil
}

// readOSVDir reads every *.json file in dir (excluding the enrichment files) as
// one OSV document.
func readOSVDir(dir string) ([][]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("vuln update: read %q: %w", dir, err)
	}
	var out [][]byte
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".json") {
			continue
		}
		if name == "epss.json" || name == "kev.json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("vuln update: read %q: %w", name, err)
		}
		out = append(out, data)
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	return out, nil
}

// loadEnrichment folds optional epss.json ({"CVE-...":0.42}) and kev.json
// (["CVE-..."]) files into the DB.
func loadEnrichment(dir string, db *DB) {
	if data, err := os.ReadFile(filepath.Join(dir, "epss.json")); err == nil {
		var m map[string]float64
		if json.Unmarshal(data, &m) == nil {
			for k, v := range m {
				db.EPSS[strings.ToUpper(k)] = v
			}
		}
	}
	if data, err := os.ReadFile(filepath.Join(dir, "kev.json")); err == nil {
		var kev []string
		if json.Unmarshal(data, &kev) == nil {
			db.KEV = dedupUpper(append(db.KEV, kev...))
		}
	}
}

// --- OSV normalization ---------------------------------------------------

type osvRecord struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Modified string   `json:"modified"`
	Publishe string   `json:"published"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			PURL      string `json:"purl"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
			} `json:"events"`
		} `json:"ranges"`
		DatabaseSpecific struct {
			Severity string `json:"severity"`
		} `json:"database_specific"`
		EcosystemSpecific struct {
			Imports []struct {
				Path    string   `json:"path"`
				Symbols []string `json:"symbols"`
			} `json:"imports"`
		} `json:"ecosystem_specific"`
	} `json:"affected"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	DatabaseSpecific struct {
		Severity string   `json:"severity"`
		CWEIDs   []string `json:"cwe_ids"`
	} `json:"database_specific"`
}

// normalizeOSV converts one OSV document into zero or more Advisories (one per
// affected package). It is the single funnel through which OSV-shaped feeds —
// GHSA, PyPI, Go, distro OSV exports — enter the store.
func normalizeOSV(doc []byte) ([]Advisory, error) {
	var rec osvRecord
	if err := json.Unmarshal(doc, &rec); err != nil {
		return nil, fmt.Errorf("parse osv record: %w", err)
	}
	if rec.ID == "" {
		return nil, fmt.Errorf("osv record: missing id")
	}

	refs := make([]string, 0, len(rec.References))
	for _, r := range rec.References {
		if r.URL != "" {
			refs = append(refs, r.URL)
		}
	}
	cvss, sev := severityFromOSV(rec)

	var out []Advisory
	for _, aff := range rec.Affected {
		eco := mapOSVEcosystem(aff.Package.Ecosystem)
		if eco == "" || aff.Package.Name == "" {
			continue
		}
		ranges := convertOSVRanges(aff.Ranges, eco)
		if len(ranges) == 0 {
			continue
		}
		name := aff.Package.Name
		if scheme(eco) == SchemePEP440 {
			name = NormalizePyPI(name)
		}
		advSev := sev
		if w := NormalizeSeverityWord(firstNonEmpty(aff.DatabaseSpecific.Severity, rec.DatabaseSpecific.Severity)); w != SevUnknown && advSev == SevUnknown {
			advSev = w
		}
		var symbols []string
		for _, imp := range aff.EcosystemSpecific.Imports {
			symbols = append(symbols, imp.Symbols...)
		}
		adv := Advisory{
			ID:         rec.ID,
			Aliases:    dedupStrings(rec.Aliases),
			Summary:    firstNonEmpty(rec.Summary, truncate(rec.Details, 200)),
			Ecosystem:  eco,
			Package:    name,
			Ranges:     ranges,
			Severity:   advSev,
			CWEs:       dedupStrings(rec.DatabaseSpecific.CWEIDs),
			Symbols:    dedupStrings(symbols),
			References: dedupStrings(refs),
			Source:     "osv",
			Published:  rec.Publishe,
			Modified:   rec.Modified,
		}
		if cvss != nil {
			cp := *cvss
			adv.CVSS = &cp
		}
		out = append(out, adv)
	}
	return out, nil
}

// severityFromOSV extracts a CVSS metric (preferring the highest-version vector)
// and a normalized severity band from an OSV record.
func severityFromOSV(rec osvRecord) (*CVSS, Severity) {
	var best *CVSS
	for _, s := range rec.Severity {
		if c, ok := ParseCVSSVector(s.Score); ok {
			if best == nil || c.Score > best.Score {
				cp := c
				best = &cp
			}
		}
	}
	if best != nil {
		return best, SeverityFromScore(best.Score)
	}
	return nil, NormalizeSeverityWord(rec.DatabaseSpecific.Severity)
}

// convertOSVRanges walks OSV event lists into closed [introduced, fixed) or
// [introduced, last_affected] intervals. SEMVER ranges keep semver semantics;
// ECOSYSTEM ranges use the package ecosystem's scheme; GIT ranges are dropped
// (commit ranges are not version-comparable).
func convertOSVRanges(osvRanges []struct {
	Type   string `json:"type"`
	Events []struct {
		Introduced   string `json:"introduced"`
		Fixed        string `json:"fixed"`
		LastAffected string `json:"last_affected"`
	} `json:"events"`
}, eco Ecosystem) []Range {
	var out []Range
	for _, r := range osvRanges {
		if strings.EqualFold(r.Type, "GIT") {
			continue
		}
		var override VersionScheme
		if strings.EqualFold(r.Type, "SEMVER") && scheme(eco) != SchemeSemver {
			override = SchemeSemver
		}
		cur := Range{Scheme: override}
		open := false
		for _, ev := range r.Events {
			switch {
			case ev.Introduced != "":
				if open {
					out = append(out, cur)
				}
				cur = Range{Scheme: override, Introduced: ev.Introduced}
				open = true
			case ev.Fixed != "":
				cur.Fixed = ev.Fixed
				out = append(out, cur)
				cur = Range{Scheme: override}
				open = false
			case ev.LastAffected != "":
				cur.LastAffected = ev.LastAffected
				out = append(out, cur)
				cur = Range{Scheme: override}
				open = false
			}
		}
		if open {
			out = append(out, cur) // open-ended range, no fix
		}
	}
	return out
}

// mapOSVEcosystem maps OSV ecosystem names to our internal ecosystem ids. OSV
// suffixes distro ecosystems with a version (e.g. "Alpine:v3.19"); we key on
// the base distro and rely on version ranges for branch specificity.
func mapOSVEcosystem(e string) Ecosystem {
	base := strings.ToLower(cutAt(e, ':'))
	switch base {
	case "npm":
		return "npm"
	case "pypi":
		return "pypi"
	case "go":
		return "go"
	case "maven":
		return "maven"
	case "crates.io":
		return "cargo"
	case "rubygems":
		return "rubygems"
	case "packagist":
		return "composer"
	case "nuget":
		return "nuget"
	case "alpine":
		return "alpine"
	case "debian":
		return "debian"
	case "ubuntu":
		return "ubuntu"
	case "red hat", "redhat", "rocky linux", "almalinux", "alma":
		return "rhel"
	case "wolfi", "chainguard":
		return "wolfi"
	default:
		if base == "" {
			return ""
		}
		return Ecosystem(base)
	}
}

// --- Alias de-duplication ------------------------------------------------

// mergeByAlias folds advisories that describe the same vulnerability (same
// canonical CVE) for the same (ecosystem, package) into one record, unioning
// ranges, aliases and references and keeping the strongest severity. This is
// how NVD/GHSA/OSV/distro views of one CVE collapse to a single finding.
func mergeByAlias(in []Advisory) []Advisory {
	order := make([]string, 0, len(in))
	groups := map[string]*Advisory{}
	for i := range in {
		a := in[i]
		key := string(a.Ecosystem) + "|" + a.Package + "|" + canonicalID(a.ids())
		g, ok := groups[key]
		if !ok {
			cp := a
			groups[key] = &cp
			order = append(order, key)
			continue
		}
		mergeAdvisory(g, a)
	}
	out := make([]Advisory, 0, len(order))
	for _, k := range order {
		g := groups[k]
		g.Aliases = dedupStrings(g.Aliases)
		g.References = dedupStrings(g.References)
		g.Ranges = dedupRanges(g.Ranges)
		out = append(out, *g)
	}
	return out
}

func mergeAdvisory(dst *Advisory, src Advisory) {
	dst.Ranges = append(dst.Ranges, src.Ranges...)
	dst.Aliases = append(dst.Aliases, src.ID)
	dst.Aliases = append(dst.Aliases, src.Aliases...)
	dst.References = append(dst.References, src.References...)
	dst.CWEs = dedupStrings(append(dst.CWEs, src.CWEs...))
	dst.Symbols = dedupStrings(append(dst.Symbols, src.Symbols...))
	if src.Severity.Rank() > dst.Severity.Rank() {
		dst.Severity = src.Severity
	}
	if dst.CVSS == nil && src.CVSS != nil {
		dst.CVSS = src.CVSS
	} else if src.CVSS != nil && dst.CVSS != nil && src.CVSS.Score > dst.CVSS.Score {
		dst.CVSS = src.CVSS
	}
	if dst.Summary == "" {
		dst.Summary = src.Summary
	}
	// Prefer a CVE as the primary id when the current primary is not one.
	if !isCVE(dst.ID) && isCVE(src.ID) {
		dst.Aliases = append(dst.Aliases, dst.ID)
		dst.ID = src.ID
	}
}

// canonicalID picks a stable grouping key: the first CVE among the ids, else
// the first id. Grouping on the CVE is what makes cross-feed de-dup work.
func canonicalID(ids []string) string {
	for _, id := range ids {
		if isCVE(id) {
			return strings.ToUpper(id)
		}
	}
	if len(ids) > 0 {
		return ids[0]
	}
	return ""
}

func isCVE(id string) bool { return strings.HasPrefix(strings.ToUpper(id), "CVE-") }

func dedupRanges(rs []Range) []Range {
	seen := map[Range]bool{}
	var out []Range
	for _, r := range rs {
		if seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func dedupUpper(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		u := strings.ToUpper(strings.TrimSpace(s))
		if u == "" || seen[u] {
			continue
		}
		seen[u] = true
		out = append(out, u)
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
