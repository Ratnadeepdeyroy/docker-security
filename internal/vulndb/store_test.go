package vulndb

import (
	"strings"
	"testing"
	"time"
)

const sampleDB = `{
  "schema": 1,
  "built_at": "2026-01-01T00:00:00Z",
  "source": "test",
  "advisories": [
    {
      "id": "CVE-2021-23337",
      "aliases": ["GHSA-35jh-r3h4-6jhm"],
      "ecosystem": "npm",
      "package": "lodash",
      "ranges": [{"introduced": "0", "fixed": "4.17.21"}],
      "severity": "high"
    },
    {
      "id": "CVE-2020-0000",
      "ecosystem": "pypi",
      "package": "Flask",
      "ranges": [{"introduced": "0", "fixed": "1.0"}],
      "severity": "medium"
    }
  ],
  "epss": {"CVE-2021-23337": 0.42},
  "kev": ["cve-2021-23337"]
}`

func loadSample(t *testing.T) *DB {
	t.Helper()
	db, err := LoadJSON([]byte(sampleDB))
	if err != nil {
		t.Fatalf("LoadJSON: %v", err)
	}
	return db
}

func TestQueryByCoord(t *testing.T) {
	db := loadSample(t)
	got := db.Query(Coord{Ecosystem: "npm", Package: "lodash"})
	if len(got) != 1 || got[0].ID != "CVE-2021-23337" {
		t.Fatalf("Query npm/lodash = %+v", got)
	}
	// PyPI names are normalized on both sides: query "flask" hits advisory "Flask".
	if got := db.Query(Coord{Ecosystem: "pypi", Package: "flask"}); len(got) != 1 {
		t.Errorf("Query pypi/flask (normalized) returned %d, want 1", len(got))
	}
	if got := db.Query(Coord{Ecosystem: "npm", Package: "express"}); len(got) != 0 {
		t.Errorf("Query for absent package returned %d advisories", len(got))
	}
}

// TestIndicesForAndAt is a regression/equivalence test for the copy-avoiding
// hot-path API (used by internal/modules/vuln/match.go instead of Query): the
// (index, At) pair must return exactly the same advisories, in the same
// order, as the copying Query API, and At must be a live pointer into the
// DB's own Advisories slice (not a fresh copy) so callers really do avoid an
// allocation/copy per lookup.
func TestIndicesForAndAt(t *testing.T) {
	db := loadSample(t)

	coord := Coord{Ecosystem: "npm", Package: "lodash"}
	want := db.Query(coord)
	idxs := db.IndicesFor(coord)
	if len(idxs) != len(want) {
		t.Fatalf("IndicesFor returned %d indices, Query returned %d advisories", len(idxs), len(want))
	}
	for n, i := range idxs {
		got := db.At(i)
		if got.ID != want[n].ID {
			t.Errorf("At(%d).ID = %q, want %q (from Query)", i, got.ID, want[n].ID)
		}
		if got != &db.Advisories[i] {
			t.Errorf("At(%d) did not return a pointer into db.Advisories (want &db.Advisories[%d])", i, i)
		}
	}

	if got := db.IndicesFor(Coord{Ecosystem: "npm", Package: "express"}); len(got) != 0 {
		t.Errorf("IndicesFor for an absent package returned %d indices", len(got))
	}
}

func TestEnrichmentLookups(t *testing.T) {
	db := loadSample(t)
	// EPSS is keyed by CVE; look it up via the advisory's alias set.
	if p, ok := db.EPSSFor([]string{"GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"}); !ok || p != 0.42 {
		t.Errorf("EPSSFor = %v,%v want 0.42,true", p, ok)
	}
	// KEV entries are matched case-insensitively.
	if !db.IsKEV([]string{"CVE-2021-23337"}) {
		t.Errorf("IsKEV should be true for CVE-2021-23337")
	}
	if db.IsKEV([]string{"CVE-2020-0000"}) {
		t.Errorf("IsKEV should be false for a non-KEV CVE")
	}
}

func TestStaleness(t *testing.T) {
	db := loadSample(t) // built 2026-01-01
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	if !db.Stale(now, 30*24*time.Hour) {
		t.Errorf("db built 2026-01-01 should be stale as of 2026-03-01")
	}
	// A zero clock disables the check (determinism).
	if db.Stale(time.Time{}, 30*24*time.Hour) {
		t.Errorf("zero now must disable staleness")
	}
	if got := db.Age(now); got <= 0 {
		t.Errorf("Age should be positive, got %v", got)
	}
}

func TestMarshalIsDeterministic(t *testing.T) {
	db := loadSample(t)
	a, err := db.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// Reloading and re-marshaling must be byte-identical.
	db2, err := LoadJSON(a)
	if err != nil {
		t.Fatal(err)
	}
	b, err := db2.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Errorf("Marshal is not stable across a load round-trip")
	}
}

func TestRejectsNewerSchema(t *testing.T) {
	if _, err := LoadJSON([]byte(`{"schema": 999, "advisories": []}`)); err == nil {
		t.Errorf("LoadJSON should reject a newer schema")
	}
}

func TestEmbeddedDefaultLoads(t *testing.T) {
	db, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if db.Count() == 0 {
		t.Errorf("embedded default DB is empty")
	}
	// The embedded snapshot must find Log4Shell in a vulnerable log4j-core.
	got := db.Query(Coord{Ecosystem: "maven", Package: "org.apache.logging.log4j:log4j-core"})
	if len(got) == 0 {
		t.Fatalf("embedded DB missing log4j-core advisory")
	}
	if !Vulnerable(SchemeMaven, "2.14.1", got[0].Ranges) {
		t.Errorf("log4j-core 2.14.1 should be vulnerable to %s", got[0].ID)
	}
	if !db.IsKEV(got[0].ids()) {
		t.Errorf("Log4Shell should be flagged KEV in the embedded DB")
	}
}

// TestEmbeddedSnapshotBreadth guards against the snapshot silently regressing to
// a near-empty stub: it must carry real advisories across many ecosystems, and
// every EPSS/KEV enrichment id must reference an advisory actually in the DB
// (a dangling enrichment id is a data-entry bug that would never fire).
func TestEmbeddedSnapshotBreadth(t *testing.T) {
	db, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if db.Count() < 40 {
		t.Errorf("embedded snapshot has only %d advisories; expected a substantial bootstrap set (>=40)", db.Count())
	}

	ecos := map[Ecosystem]bool{}
	knownIDs := map[string]bool{}
	for _, a := range db.Advisories {
		ecos[a.Ecosystem] = true
		for _, id := range a.ids() {
			knownIDs[strings.ToUpper(id)] = true
		}
		if len(a.Ranges) == 0 {
			t.Errorf("advisory %s (%s/%s) has no ranges — it can never match", a.ID, a.Ecosystem, a.Package)
		}
	}
	// Must span both OS-package and language ecosystems for the snapshot to be
	// useful on a real image (base layers + app dependencies).
	wantEco := []Ecosystem{"maven", "npm", "pypi", "go", "debian", "alpine", "rhel", "ubuntu"}
	for _, e := range wantEco {
		if !ecos[e] {
			t.Errorf("embedded snapshot missing ecosystem %q", e)
		}
	}

	for id := range db.EPSS {
		if !knownIDs[strings.ToUpper(id)] {
			t.Errorf("EPSS score references unknown advisory id %q", id)
		}
	}
	for _, id := range db.KEV {
		if !knownIDs[strings.ToUpper(id)] {
			t.Errorf("KEV entry references unknown advisory id %q", id)
		}
	}
}

// TestEmbeddedSnapshotReserializes confirms the shipped snapshot is already in
// canonical form, so `dsecrat vuln db update` output stays byte-stable and a
// re-serialize round-trips without loss.
func TestEmbeddedSnapshotReserializes(t *testing.T) {
	db, err := Default()
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if _, err := db.Marshal(); err != nil {
		t.Fatalf("Marshal embedded snapshot: %v", err)
	}
}
