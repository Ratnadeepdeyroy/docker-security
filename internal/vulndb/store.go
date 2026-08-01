package vulndb

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// --- The advisory store --------------------------------------------------

// currentSchema is the on-disk format version. Load refuses a newer schema it
// cannot understand rather than silently mis-reading advisories.
const currentSchema = 1

// DB is a loaded, indexed advisory database. The JSON fields are the on-disk
// format; the unexported index fields are rebuilt on load and never serialized,
// so a re-serialized DB is byte-stable.
type DB struct {
	Schema     int                `json:"schema"`
	BuiltAt    time.Time          `json:"built_at"`
	Source     string             `json:"source,omitempty"`
	Advisories []Advisory         `json:"advisories"`
	EPSS       map[string]float64 `json:"epss,omitempty"` // CVE id → exploit probability [0,1]
	KEV        []string           `json:"kev,omitempty"`  // CVEs in CISA's Known Exploited catalog

	// SkippedRecords counts per-record parse failures encountered while
	// building this DB via Update (malformed OSV documents that normalizeOSV
	// rejected). It's a diagnostic counter for the rebuild that produced this
	// *DB value, not persisted state — deliberately excluded from JSON so it
	// never affects Marshal's byte-reproducible output, and zero (not present)
	// for any DB loaded via Open/LoadJSON rather than freshly built.
	SkippedRecords int `json:"-"`

	byPkg  map[string][]int // "ecosystem|package" → indices into Advisories
	kevSet map[string]bool
}

// Open loads a DB from a JSON file on disk.
func Open(path string) (*DB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("open advisory db %q: %w", path, err)
	}
	db, err := LoadJSON(data)
	if err != nil {
		return nil, fmt.Errorf("open advisory db %q: %w", path, err)
	}
	return db, nil
}

// LoadJSON parses and indexes a DB from its JSON bytes.
func LoadJSON(data []byte) (*DB, error) {
	var db DB
	if err := json.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("parse advisory db: %w", err)
	}
	if db.Schema > currentSchema {
		return nil, fmt.Errorf("advisory db schema %d is newer than supported %d; upgrade dsecrat", db.Schema, currentSchema)
	}
	db.index()
	return &db, nil
}

// index builds the package and KEV lookup structures.
func (db *DB) index() {
	db.byPkg = make(map[string][]int, len(db.Advisories))
	for i := range db.Advisories {
		key := indexKey(db.Advisories[i].Ecosystem, db.Advisories[i].Package)
		db.byPkg[key] = append(db.byPkg[key], i)
	}
	db.kevSet = make(map[string]bool, len(db.KEV))
	for _, id := range db.KEV {
		db.kevSet[strings.ToUpper(id)] = true
	}
}

// indexKey normalizes an (ecosystem, package) pair into a stable lookup key.
// PyPI names are PEP 503-normalized so "Flask" and "flask" collide correctly.
func indexKey(eco Ecosystem, pkg string) string {
	e := strings.ToLower(string(eco))
	if scheme(eco) == SchemePEP440 {
		pkg = NormalizePyPI(pkg)
	}
	return e + "|" + pkg
}

// Query returns the advisories that apply to a component coordinate. It returns
// a fresh slice; callers may reorder it freely.
//
// This copies every candidate Advisory by value, which is convenient for
// callers that want an owned, reorderable slice (tests, CLI diagnostics) but
// is wasted allocation/copy work in the vuln module's per-component hot loop,
// which only reads fields and never needs ownership. That loop should prefer
// IndicesFor + At instead (see match.go).
func (db *DB) Query(c Coord) []Advisory {
	if db == nil {
		return nil
	}
	idxs := db.IndicesFor(c)
	if len(idxs) == 0 {
		return nil
	}
	out := make([]Advisory, 0, len(idxs))
	for _, i := range idxs {
		out = append(out, db.Advisories[i])
	}
	return out
}

// IndicesFor returns the raw indices into Advisories that apply to a component
// coordinate, without copying any Advisory. The returned slice aliases the
// DB's internal index (db.byPkg) — callers must treat it as read-only and must
// not mutate it, and it is only valid for the lifetime of db (which is never
// mutated after LoadJSON/Update build it, so this is safe to hold as long as
// db itself is reachable).
func (db *DB) IndicesFor(c Coord) []int {
	if db == nil {
		return nil
	}
	return db.byPkg[indexKey(c.Ecosystem, c.Package)]
}

// At returns a pointer to the advisory at index i (as returned by
// IndicesFor), avoiding a struct copy. It panics on an out-of-range i, exactly
// like a slice index — callers are expected to only pass indices obtained
// from IndicesFor on the same db.
func (db *DB) At(i int) *Advisory {
	return &db.Advisories[i]
}

// EPSSFor returns the EPSS exploit probability for the first of ids that has a
// score, and whether one was found. EPSS is keyed by CVE, which may be an
// advisory alias rather than its primary id.
func (db *DB) EPSSFor(ids []string) (float64, bool) {
	if db == nil {
		return 0, false
	}
	for _, id := range ids {
		if p, ok := db.EPSS[strings.ToUpper(id)]; ok {
			return p, true
		}
	}
	return 0, false
}

// IsKEV reports whether any of ids is in CISA's Known Exploited Vulnerabilities
// catalog — the single strongest "fix this now" signal, independent of CVSS.
func (db *DB) IsKEV(ids []string) bool {
	if db == nil {
		return false
	}
	for _, id := range ids {
		if db.kevSet[strings.ToUpper(id)] {
			return true
		}
	}
	return false
}

// Age returns how old the database is relative to now. Callers inject now so
// staleness never depends on the ambient clock inside analysis.
func (db *DB) Age(now time.Time) time.Duration {
	if db == nil || db.BuiltAt.IsZero() || now.IsZero() {
		return 0
	}
	return now.Sub(db.BuiltAt)
}

// Stale reports whether the DB is older than maxAge as of now. A zero now or
// BuiltAt disables the check (returns false) so tests stay deterministic.
func (db *DB) Stale(now time.Time, maxAge time.Duration) bool {
	if db == nil || db.BuiltAt.IsZero() || now.IsZero() || maxAge <= 0 {
		return false
	}
	return now.Sub(db.BuiltAt) > maxAge
}

// Count returns the number of advisories, for diagnostics.
func (db *DB) Count() int {
	if db == nil {
		return 0
	}
	return len(db.Advisories)
}

// Marshal serializes the DB back to canonical JSON: advisories sorted by
// (ecosystem, package, id) and KEV sorted, so `db update` output is
// byte-reproducible for the same inputs.
func (db *DB) Marshal() ([]byte, error) {
	out := *db
	out.Advisories = append([]Advisory(nil), db.Advisories...)
	sort.SliceStable(out.Advisories, func(i, j int) bool {
		a, b := out.Advisories[i], out.Advisories[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.ID < b.ID
	})
	out.KEV = append([]string(nil), db.KEV...)
	sort.Strings(out.KEV)
	data, err := json.MarshalIndent(&out, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal advisory db: %w", err)
	}
	return append(data, '\n'), nil
}
