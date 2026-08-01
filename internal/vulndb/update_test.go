package vulndb

import (
	"context"
	"strings"
	"testing"
	"time"
)

func buildFromFeeds(t *testing.T) *DB {
	t.Helper()
	db, err := Update(context.Background(), Options{
		FromDir: "testdata/feeds",
		Now:     time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		Source:  "test-feeds",
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	return db
}

func TestUpdateMergesByAlias(t *testing.T) {
	db := buildFromFeeds(t)

	// The GHSA and NVD records for lodash describe the same CVE and must collapse
	// into a single advisory. Combined with the Go record, that is 2 advisories
	// (the broken feed file is skipped, not fatal).
	if db.Count() != 2 {
		t.Fatalf("advisory count = %d, want 2 (merged lodash + go); dump: %s", db.Count(), mustMarshal(t, db))
	}

	lodash := db.Query(Coord{Ecosystem: "npm", Package: "lodash"})
	if len(lodash) != 1 {
		t.Fatalf("expected 1 merged lodash advisory, got %d", len(lodash))
	}
	adv := lodash[0]
	if adv.ID != "CVE-2021-23337" {
		t.Errorf("merged primary id = %q, want CVE-2021-23337 (CVE preferred over GHSA)", adv.ID)
	}
	if !containsStr(adv.Aliases, "GHSA-35jh-r3h4-6jhm") {
		t.Errorf("merged aliases missing GHSA id: %v", adv.Aliases)
	}
	if adv.Severity != SevHigh {
		t.Errorf("merged severity = %q, want high", adv.Severity)
	}
	if adv.CVSS == nil {
		t.Errorf("merged advisory lost its CVSS metric")
	}
	if !Vulnerable(SchemeSemver, "4.17.20", adv.Ranges) || Vulnerable(SchemeSemver, "4.17.21", adv.Ranges) {
		t.Errorf("merged range semantics wrong: %+v", adv.Ranges)
	}
}

func TestUpdateNormalizesSymbolsAndEnrichment(t *testing.T) {
	db := buildFromFeeds(t)

	goAdv := db.Query(Coord{Ecosystem: "go", Package: "github.com/example/vuln"})
	if len(goAdv) != 1 {
		t.Fatalf("expected 1 go advisory, got %d", len(goAdv))
	}
	if !containsStr(goAdv[0].Symbols, "Parse") || !containsStr(goAdv[0].Symbols, "unsafeDecode") {
		t.Errorf("go advisory symbols = %v, want Parse + unsafeDecode", goAdv[0].Symbols)
	}

	if p, ok := db.EPSSFor([]string{"CVE-2021-23337"}); !ok || p != 0.42 {
		t.Errorf("EPSS overlay not loaded: %v,%v", p, ok)
	}
	if !db.IsKEV([]string{"CVE-2021-23337"}) {
		t.Errorf("KEV overlay not loaded")
	}
}

// TestUpdateCountsSkippedRecords is a regression test for silently dropping
// per-record parse failures: testdata/feeds/broken.json is deliberately
// malformed JSON, and normalizeOSV's error for it must be counted rather than
// just swallowed by the "continue", so a partially-corrupt feed is visible to
// whoever runs `dsecrat vuln update` instead of only showing up as a mysteriously
// low advisory count.
func TestUpdateCountsSkippedRecords(t *testing.T) {
	db := buildFromFeeds(t)
	if db.SkippedRecords != 1 {
		t.Errorf("SkippedRecords = %d, want 1 (testdata/feeds/broken.json)", db.SkippedRecords)
	}
}

// TestUpdateSkippedRecordsExcludedFromMarshal confirms the diagnostic counter
// never leaks into the persisted DB format: it must not appear in Marshal's
// output and must not affect determinism (TestUpdateIsDeterministic already
// checks the marshal is stable; this checks the specific field is absent).
func TestUpdateSkippedRecordsExcludedFromMarshal(t *testing.T) {
	db := buildFromFeeds(t)
	if db.SkippedRecords == 0 {
		t.Fatal("test setup: expected buildFromFeeds to have skipped at least one record")
	}
	data := mustMarshal(t, db)
	if strings.Contains(data, "SkippedRecords") || strings.Contains(data, "skipped_records") {
		t.Errorf("Marshal output must not contain the SkippedRecords diagnostic field:\n%s", data)
	}
}

func TestUpdateIsDeterministic(t *testing.T) {
	a := mustMarshal(t, buildFromFeeds(t))
	b := mustMarshal(t, buildFromFeeds(t))
	if a != b {
		t.Errorf("db update output is not deterministic across runs")
	}
}

// fakeFetcher exercises the opt-in network path without touching the wire.
type fakeFetcher struct{ docs [][]byte }

func (f fakeFetcher) Fetch(context.Context) ([][]byte, error) { return f.docs, nil }

func TestUpdateWithFetcher(t *testing.T) {
	doc := []byte(`{"id":"CVE-2099-9999","affected":[{"package":{"ecosystem":"npm","name":"leftpad"},
	  "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}],
	  "database_specific":{"severity":"CRITICAL"}}]}`)
	db, err := Update(context.Background(), Options{
		Fetcher: fakeFetcher{docs: [][]byte{doc}},
		Now:     time.Unix(0, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	got := db.Query(Coord{Ecosystem: "npm", Package: "leftpad"})
	if len(got) != 1 || got[0].Severity != SevCritical {
		t.Errorf("fetcher path advisory = %+v", got)
	}
}

func mustMarshal(t *testing.T, db *DB) string {
	t.Helper()
	b, err := db.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func containsStr(s []string, want string) bool {
	for _, v := range s {
		if v == want {
			return true
		}
	}
	return false
}
