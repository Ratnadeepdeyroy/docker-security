package vulndb

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// This file implements live EPSS (Exploit Prediction Scoring System) ingestion.
// EPSS gives each CVE a 0..1 probability of exploitation in the next 30 days;
// the vuln module folds it into prioritization (see priority.go). Previously the
// only EPSS data was the small static overlay baked into the bootstrap snapshot
// (and any manual epss.json); this fetcher pulls the full daily scoreset that
// FIRST publishes, so priorities reflect current real-world exploitation
// likelihood for the whole CVE corpus, not just the seed.
//
// It is opt-in network access, mirroring the OSV/NVD fetchers.

// DefaultEPSSURL is FIRST's daily full EPSS scoreset (gzipped CSV). The endpoint
// 302-redirects to the current dated file, so the client must follow redirects
// (net/http does by default).
const DefaultEPSSURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"

// maxEPSSBytes caps the decompressed CSV read so a hostile/misconfigured mirror
// cannot exhaust memory. The real scoreset is ~10 MiB of CSV for ~280k CVEs.
const maxEPSSBytes = 128 << 20

// EPSSFetcher pulls the full EPSS scoreset over HTTP(S). Zero value is unusable;
// build one with NewEPSSFetcher.
type EPSSFetcher struct {
	URL    string
	Client *http.Client
}

// NewEPSSFetcher returns a fetcher for url (DefaultEPSSURL when empty) with a
// bounded timeout.
func NewEPSSFetcher(url string) *EPSSFetcher {
	if url == "" {
		url = DefaultEPSSURL
	}
	return &EPSSFetcher{URL: url, Client: &http.Client{Timeout: 120 * time.Second}}
}

// Fetch downloads and parses the scoreset into a CVE→probability map.
func (f *EPSSFetcher) Fetch(ctx context.Context) (map[string]float64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("epss fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("epss fetch: unexpected status %d for %s", resp.StatusCode, f.URL)
	}
	var body io.Reader = io.LimitReader(resp.Body, maxEPSSBytes)
	// The endpoint serves a .csv.gz; if the transport already transparently
	// decompressed it (resp.Uncompressed), the body is plain CSV. Detect by
	// peeking the gzip magic.
	br := bufio.NewReader(body)
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, fmt.Errorf("epss fetch: gzip: %w", err)
		}
		defer gz.Close()
		return ParseEPSSCSV(io.LimitReader(gz, maxEPSSBytes))
	}
	return ParseEPSSCSV(br)
}

// ParseEPSSCSV parses the EPSS CSV (pure, testable). The file starts with a
// `#model_version,score_date` comment line, then a `cve,epss,percentile` header,
// then one row per CVE. It tolerates the comment/header in any leading position
// and skips malformed rows. Returns CVE(upper)→epss.
func ParseEPSSCSV(r io.Reader) (map[string]float64, error) {
	out := make(map[string]float64, 300000)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) < 2 {
			continue
		}
		cve := strings.ToUpper(strings.TrimSpace(fields[0]))
		if !strings.HasPrefix(cve, "CVE-") {
			continue // header row ("cve,...") or junk
		}
		score, err := strconv.ParseFloat(strings.TrimSpace(fields[1]), 64)
		if err != nil {
			continue
		}
		out[cve] = score
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("epss parse: %w", err)
	}
	return out, nil
}
