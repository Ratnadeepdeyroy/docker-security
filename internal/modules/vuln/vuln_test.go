package vuln

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/vulndb"
)

// writeFixture lays out a filesystem target with a known-vulnerable lodash and
// requests, both of which the embedded advisory DB flags.
func writeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mkdir := func(p string) string {
		full := filepath.Join(dir, p)
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatal(err)
		}
		return full
	}
	// npm lodash 4.17.20 (< 4.17.21 → CVE-2021-23337)
	lp := mkdir("app/node_modules/lodash")
	os.WriteFile(filepath.Join(lp, "package.json"), []byte(`{"name":"lodash","version":"4.17.20"}`), 0o644)
	// pypi requests 2.30.0 (< 2.31.0 → CVE-2023-32681)
	rp := mkdir("usr/lib/python3.11/site-packages/requests-2.30.0.dist-info")
	os.WriteFile(filepath.Join(rp, "METADATA"), []byte("Name: requests\nVersion: 2.30.0\n\n"), 0o644)
	return dir
}

func TestSupports(t *testing.T) {
	m := New()
	if !m.Supports(engine.TargetImage) || !m.Supports(engine.TargetFilesystem) {
		t.Error("vuln must support image and filesystem targets")
	}
	if m.Supports(engine.TargetDockerfile) {
		t.Error("vuln must not support dockerfile targets")
	}
}

func TestAnalyzeMatchesSeededAdvisories(t *testing.T) {
	m := New()
	findings, err := m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetFilesystem,
		Location: writeFixture(t),
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	byRule := map[string]engine.Finding{}
	for _, f := range findings {
		byRule[f.RuleID] = f
	}
	// Both CVEs from the embedded bootstrap DB must be reported.
	lodash, ok := byRule["DS-RAT-VULN-CVE-2021-23337"]
	if !ok {
		t.Fatalf("expected DS-RAT-VULN-CVE-2021-23337 (lodash); got rules %v", keys(byRule))
	}
	if lodash.Severity != engine.SeverityHigh {
		t.Errorf("lodash CVE severity = %s, want HIGH", lodash.Severity)
	}
	if _, ok := byRule["DS-RAT-VULN-CVE-2023-32681"]; !ok {
		t.Errorf("expected DS-RAT-VULN-CVE-2023-32681 (requests); got rules %v", keys(byRule))
	}
}

func TestAnalyzeCleanTreeHasNoCVEFindings(t *testing.T) {
	// A fixed lodash must NOT match (proves the version comparator, not just name).
	dir := t.TempDir()
	lp := filepath.Join(dir, "node_modules", "lodash")
	if err := os.MkdirAll(lp, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(lp, "package.json"), []byte(`{"name":"lodash","version":"4.17.21"}`), 0o644)

	findings, err := New().Analyze(context.Background(), &engine.Target{Type: engine.TargetFilesystem, Location: dir})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "DS-RAT-VULN-CVE-2021-23337" {
			t.Errorf("fixed lodash 4.17.21 must not match CVE-2021-23337")
		}
	}
}

func TestAnalyzeFlagsEOLDistro(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "etc", "os-release"), []byte("ID=alpine\nVERSION_ID=3.16.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	m := NewWithOptions(Options{Now: time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC)})
	findings, err := m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetFilesystem,
		Location: dir,
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	byRule := map[string]engine.Finding{}
	for _, f := range findings {
		byRule[f.RuleID] = f
	}
	eol, ok := byRule["DS-RAT-VULN-EOL"]
	if !ok {
		t.Fatalf("expected DS-RAT-VULN-EOL for EOL alpine 3.16.0; got rules %v", keys(byRule))
	}
	if eol.Severity != engine.SeverityHigh {
		t.Errorf("EOL finding severity = %s, want HIGH", eol.Severity)
	}
}

// syntheticDB writes a minimal internal-schema advisory DB with one advisory
// for the npm package "leftpad" at the given version, plus the given source
// label so tests can distinguish which DB actually got loaded.
func syntheticDB(t *testing.T, source, version string) string {
	t.Helper()
	dbJSON := `{
  "schema": 1,
  "built_at": "2026-01-01T00:00:00Z",
  "source": "` + source + `",
  "advisories": [
    {
      "id": "CVE-2099-0001",
      "ecosystem": "npm",
      "package": "leftpad",
      "ranges": [{"introduced": "0", "fixed": "` + version + `"}],
      "severity": "high"
    }
  ]
}`
	path := filepath.Join(t.TempDir(), "vulndb.json")
	if err := os.WriteFile(path, []byte(dbJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// npmFixture builds a filesystem target with a single npm package at a fixed
// version, vulnerable to anything with a "fixed" version above it.
func npmFixture(t *testing.T, version string) string {
	t.Helper()
	dir := t.TempDir()
	lp := filepath.Join(dir, "node_modules", "leftpad")
	if err := os.MkdirAll(lp, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"name":"leftpad","version":"` + version + `"}`
	if err := os.WriteFile(filepath.Join(lp, "package.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestResolveDB_DifferentDBPathPerAnalyzeCall is a regression test for the
// sync.Once staleness bug: resolveDB used to memoize the DB against whatever
// DBPath the *first* Analyze call happened to use, so a later Analyze call on
// the same *Module with a different Target.Metadata["vuln.db"] silently kept
// reusing the first DB — the exact shape of `dsecrat watch --vuln-db` re-scanning
// with the same Module instance every cycle while the DB file is refreshed.
// Two Analyze calls with different DBPath values must each reflect their own
// DB's advisories.
func TestResolveDB_DifferentDBPathPerAnalyzeCall(t *testing.T) {
	dbA := syntheticDB(t, "db-a", "1.0.0") // leftpad < 1.0.0 vulnerable
	dbB := syntheticDB(t, "db-b", "2.0.0") // leftpad < 2.0.0 vulnerable

	dir := npmFixture(t, "1.5.0") // vulnerable per dbB's range, not dbA's

	m := New() // one Module instance reused across both calls, like `dsecrat watch`

	findingsA, err := m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetFilesystem,
		Location: dir,
		Metadata: map[string]string{"vuln.db": dbA},
	})
	if err != nil {
		t.Fatalf("Analyze (dbA): %v", err)
	}
	if hasRule(findingsA, "DS-RAT-VULN-CVE-2099-0001") {
		t.Error("dbA's range (fixed 1.0.0) must not flag leftpad 1.5.0")
	}

	findingsB, err := m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetFilesystem,
		Location: dir,
		Metadata: map[string]string{"vuln.db": dbB},
	})
	if err != nil {
		t.Fatalf("Analyze (dbB): %v", err)
	}
	if !hasRule(findingsB, "DS-RAT-VULN-CVE-2099-0001") {
		t.Error("second Analyze call with a different DBPath (dbB) must use dbB, not a memoized dbA — got no finding, want the leftpad CVE")
	}
}

// TestResolveDB_ConcurrentSameAndDifferentKeys stress-tests the per-key
// singleflight in resolveDB under -race: N goroutines resolve a mix of the
// embedded ("") path and two distinct on-disk DBPaths concurrently. Each key
// must resolve to exactly one loaded *vulndb.DB — proven by pointer identity,
// since sync.Once guarantees the loader body for a given cachedDB runs at most
// once, so every goroutine requesting the same key must observe the same
// *vulndb.DB pointer — and distinct keys must not collapse onto the same DB.
func TestResolveDB_ConcurrentSameAndDifferentKeys(t *testing.T) {
	dbA := syntheticDB(t, "db-a", "1.0.0")
	dbB := syntheticDB(t, "db-b", "2.0.0")

	m := New()
	keys := []string{"", dbA, dbB}

	const n = 60
	type result struct {
		key string
		db  *vulndb.DB
		err error
	}
	results := make(chan result, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		key := keys[i%len(keys)]
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			db, err := m.resolveDB(Options{DBPath: key})
			results <- result{key: key, db: db, err: err}
		}(key)
	}
	wg.Wait()
	close(results)

	firstForKey := map[string]*vulndb.DB{}
	for r := range results {
		if r.err != nil {
			t.Fatalf("resolveDB(%q): %v", r.key, r.err)
		}
		if prev, ok := firstForKey[r.key]; ok {
			if prev != r.db {
				t.Errorf("key %q: concurrent resolveDB calls returned different *vulndb.DB pointers (%p vs %p); want the same key to load exactly once", r.key, prev, r.db)
			}
		} else {
			firstForKey[r.key] = r.db
		}
	}
	if len(firstForKey) != len(keys) {
		t.Fatalf("expected results for all %d keys, got %d", len(keys), len(firstForKey))
	}
	if firstForKey[""] == firstForKey[dbA] || firstForKey[dbA] == firstForKey[dbB] || firstForKey[""] == firstForKey[dbB] {
		t.Error("distinct DBPaths (including the embedded \"\" path) must not resolve to the same *vulndb.DB")
	}
}

// TestAnalyzeConcurrentMixedDBPaths is the Analyze-level companion to
// TestResolveDB_ConcurrentSameAndDifferentKeys: it hammers one shared *Module
// (as `dsecrat serve`/`dsecrat watch` would) with many concurrent Analyze calls
// across a mix of the embedded DB and two distinct on-disk DBs, and asserts
// each call's findings reflect its own DBPath rather than a memoized/racy one.
// Run with -race: this is the regression test for resolveDB's old
// single-mutex-held-across-file-I/O design, which was race-free but this test
// is what would have caught a broken singleflight refactor (e.g. one that
// dropped the lock incorrectly and corrupted the map).
func TestAnalyzeConcurrentMixedDBPaths(t *testing.T) {
	dbA := syntheticDB(t, "db-a", "1.0.0") // leftpad vulnerable below 1.0.0
	dbB := syntheticDB(t, "db-b", "2.0.0") // leftpad vulnerable below 2.0.0

	dirLow := npmFixture(t, "0.5.0")  // vulnerable under both dbA and dbB
	dirMid := npmFixture(t, "1.5.0")  // vulnerable only under dbB, not dbA
	dirNone := npmFixture(t, "9.9.9") // vulnerable under neither

	m := New() // one Module instance shared across all goroutines

	type call struct {
		dbPath      string
		dir         string
		wantMatch   bool
		description string
	}
	calls := []call{
		{"", dirLow, false, "embedded db has no leftpad advisory"},
		{dbA, dirLow, true, "dbA/dirLow"},
		{dbA, dirMid, false, "dbA/dirMid (fixed at 1.0.0, 1.5.0 is not vulnerable)"},
		{dbB, dirMid, true, "dbB/dirMid (fixed at 2.0.0, 1.5.0 is vulnerable)"},
		{dbB, dirNone, false, "dbB/dirNone (9.9.9 is never vulnerable)"},
	}

	const rounds = 15
	errCh := make(chan error, rounds*len(calls))
	var wg sync.WaitGroup
	for i := 0; i < rounds; i++ {
		for _, c := range calls {
			wg.Add(1)
			go func(c call) {
				defer wg.Done()
				target := &engine.Target{
					Type:     engine.TargetFilesystem,
					Location: c.dir,
				}
				if c.dbPath != "" {
					target.Metadata = map[string]string{"vuln.db": c.dbPath}
				}
				findings, err := m.Analyze(context.Background(), target)
				if err != nil {
					errCh <- fmt.Errorf("%s: Analyze: %w", c.description, err)
					return
				}
				got := hasRule(findings, "DS-RAT-VULN-CVE-2099-0001")
				if got != c.wantMatch {
					errCh <- fmt.Errorf("%s: hasRule = %v, want %v", c.description, got, c.wantMatch)
				}
			}(c)
		}
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// TestAnalyzeContextCanceledReturnsError is a regression test for silently
// absorbing a canceled scan into a "clean" empty result: a pre-canceled ctx
// must make Analyze return a non-nil error wrapping context.Canceled, not nil
// findings with a nil error indistinguishable from "nothing to report".
func TestAnalyzeContextCanceledReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	findings, err := New().Analyze(ctx, &engine.Target{
		Type:     engine.TargetFilesystem,
		Location: writeFixture(t),
	})
	if err == nil {
		t.Fatal("Analyze with a pre-canceled context returned a nil error; want a non-nil context error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Analyze error = %v, want it to wrap context.Canceled", err)
	}
	if findings != nil {
		t.Errorf("Analyze with a pre-canceled context returned %d findings, want nil", len(findings))
	}
}

func hasRule(findings []engine.Finding, rule string) bool {
	for _, f := range findings {
		if f.RuleID == rule {
			return true
		}
	}
	return false
}

func keys(m map[string]engine.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
