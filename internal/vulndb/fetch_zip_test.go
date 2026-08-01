package vulndb

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func zipOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, body := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		f.Write([]byte(body))
	}
	w.Close()
	return buf.Bytes()
}

func TestUnzipOSV(t *testing.T) {
	data := zipOf(t, map[string]string{
		"CVE-2026-0001.json": `{"id":"CVE-2026-0001"}`,
		"CVE-2026-0002.json": `{"id":"CVE-2026-0002"}`,
		"README.md":          "not json",
	})
	recs, err := unzipOSV(context.Background(), data)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 json records, got %d", len(recs))
	}
}

// TestUnzipOSV_AggregateBudgetExceeded is a regression test for the zip-bomb
// finding: each member individually fits under the budget, but the sum
// across all members does not, and unzipOSVBudget must reject the archive
// rather than silently reading past the aggregate cap.
func TestUnzipOSV_AggregateBudgetExceeded(t *testing.T) {
	data := zipOf(t, map[string]string{
		"a.json": strings.Repeat("a", 60),
		"b.json": strings.Repeat("b", 60),
		"c.json": strings.Repeat("c", 60), // 180 bytes total > 100 byte budget
	})
	_, err := unzipOSVBudget(context.Background(), data, 100)
	if err == nil {
		t.Fatal("want an error when aggregate decompressed size exceeds the budget, got nil")
	}
}

// TestUnzipOSV_AggregateBudgetWithinLimit is the counterpart: several members
// whose sum is under the budget must all be returned normally.
func TestUnzipOSV_AggregateBudgetWithinLimit(t *testing.T) {
	data := zipOf(t, map[string]string{
		"a.json": strings.Repeat("a", 20),
		"b.json": strings.Repeat("b", 20),
	})
	recs, err := unzipOSVBudget(context.Background(), data, 100)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
}

// TestUnzipOSV_ContextCancelled asserts a cancelled context aborts expansion
// before any more members are read, rather than running to completion.
func TestUnzipOSV_ContextCancelled(t *testing.T) {
	data := zipOf(t, map[string]string{
		"a.json": `{"id":"CVE-2026-0001"}`,
		"b.json": `{"id":"CVE-2026-0002"}`,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := unzipOSV(ctx, data)
	if err == nil {
		t.Fatal("want an error from a cancelled context, got nil")
	}
}

func TestEcosystemFeedURL(t *testing.T) {
	got := EcosystemFeedURL("Debian")
	want := "https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

// TestEcosystemFeedURL_Escapes is a regression test: an ecosystem string
// with a '#' or '?' must not be parsed as a URL fragment/query, which would
// silently truncate the request path before it ever reaches "/all.zip".
func TestEcosystemFeedURL_Escapes(t *testing.T) {
	got := EcosystemFeedURL("A#B")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse %q: %v", got, err)
	}
	if u.Fragment != "" {
		t.Errorf("got fragment %q, want none (the '#' must be escaped)", u.Fragment)
	}
	if !strings.HasSuffix(u.Path, "/all.zip") {
		t.Errorf("got path %q, want it to end in /all.zip", u.Path)
	}

	got2 := EcosystemFeedURL("A?B")
	u2, err := url.Parse(got2)
	if err != nil {
		t.Fatalf("parse %q: %v", got2, err)
	}
	if u2.RawQuery != "" {
		t.Errorf("got query %q, want none (the '?' must be escaped)", u2.RawQuery)
	}
	if !strings.HasSuffix(u2.Path, "/all.zip") {
		t.Errorf("got path %q, want it to end in /all.zip", u2.Path)
	}
}

// TestHTTPFetcherServesZip covers the zip-sniff branch of HTTPFetcher.Fetch: a
// mirror that serves a PK-magic zip (OSV's own export shape) must be unpacked
// the same way an air-gapped `db update --from` directory would be read.
func TestHTTPFetcherServesZip(t *testing.T) {
	data := zipOf(t, map[string]string{
		"CVE-2026-0001.json": `{"id":"CVE-2026-0001"}`,
		"CVE-2026-0002.json": `{"id":"CVE-2026-0002"}`,
		"CVE-2026-0003.json": `{"id":"CVE-2026-0003"}`,
		"README.md":          "not json",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/zip")
		w.Write(data)
	}))
	defer srv.Close()

	f := NewHTTPFetcher(srv.URL)
	recs, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("want 3 records from the zip, got %d", len(recs))
	}
}

// TestHTTPFetcherServesJSONArray covers the fallback branch: a self-hosted
// mirror that returns a bare JSON array of OSV records (no zip wrapping) must
// still split into one document per record.
func TestHTTPFetcherServesJSONArray(t *testing.T) {
	body := `[{"id":"CVE-2026-0010"},{"id":"CVE-2026-0011"}]`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	defer srv.Close()

	f := NewHTTPFetcher(srv.URL)
	recs, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 records from the JSON array, got %d", len(recs))
	}
	if string(recs[0]) != `{"id":"CVE-2026-0010"}` {
		t.Errorf("record 0 = %s, want the raw OSV object", recs[0])
	}
}

// multiFakeFetcher is a minimal Fetcher for exercising MultiFetcher without
// any network access. update_test.go's fakeFetcher can't report an error, so
// this one adds that.
type multiFakeFetcher struct {
	recs [][]byte
	err  error
}

func (f multiFakeFetcher) Fetch(ctx context.Context) ([][]byte, error) { return f.recs, f.err }

// TestMultiFetcher_FailFast asserts the documented all-or-nothing contract: if
// any feed fails, the whole update fails rather than silently returning a
// partial database built from only the feeds that happened to succeed.
func TestMultiFetcher_FailFast(t *testing.T) {
	good := multiFakeFetcher{recs: [][]byte{[]byte(`{"id":"CVE-2026-0020"}`)}}
	bad := multiFakeFetcher{err: errors.New("feed unreachable")}

	m := &MultiFetcher{Fetchers: []Fetcher{good, bad}}
	recs, err := m.Fetch(context.Background())
	if err == nil {
		t.Fatal("want an error when one feed fails, got nil")
	}
	if recs != nil {
		t.Fatalf("want no partial records on failure, got %d", len(recs))
	}
}

// TestMultiFetcher_ConcatenatesOnSuccess is the counterpart success case: when
// every feed succeeds, MultiFetcher concatenates all of their records.
func TestMultiFetcher_ConcatenatesOnSuccess(t *testing.T) {
	a := multiFakeFetcher{recs: [][]byte{[]byte(`{"id":"CVE-2026-0030"}`)}}
	b := multiFakeFetcher{recs: [][]byte{[]byte(`{"id":"CVE-2026-0031"}`), []byte(`{"id":"CVE-2026-0032"}`)}}

	m := &MultiFetcher{Fetchers: []Fetcher{a, b}}
	recs, err := m.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("want 3 concatenated records, got %d", len(recs))
	}
}
