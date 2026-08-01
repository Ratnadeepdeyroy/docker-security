package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// This file implements live CISA KEV (Known Exploited Vulnerabilities) ingestion.
// KEV is CISA's authoritative list of CVEs with confirmed in-the-wild
// exploitation; the vuln module treats a KEV hit as a hard priority escalation
// (see priority.go). Previously the only KEV data was the ~14-entry static
// overlay in the bootstrap snapshot; this fetcher pulls the full catalog
// (~1,600+ CVEs) so prioritization reflects the current KEV list.
//
// Opt-in network access, mirroring the OSV/NVD/EPSS fetchers.

// DefaultKEVURL is CISA's machine-readable KEV catalog.
const DefaultKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// maxKEVBytes caps the read; the catalog is a few MiB of JSON.
const maxKEVBytes = 32 << 20

// KEVFetcher pulls the CISA KEV catalog over HTTP(S).
type KEVFetcher struct {
	URL    string
	Client *http.Client
}

// NewKEVFetcher returns a fetcher for url (DefaultKEVURL when empty).
func NewKEVFetcher(url string) *KEVFetcher {
	if url == "" {
		url = DefaultKEVURL
	}
	return &KEVFetcher{URL: url, Client: &http.Client{Timeout: 60 * time.Second}}
}

// Fetch downloads and parses the catalog into a sorted, de-duplicated list of
// KEV CVE IDs (uppercased).
func (f *KEVFetcher) Fetch(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kev fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kev fetch: unexpected status %d for %s", resp.StatusCode, f.URL)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxKEVBytes))
	if err != nil {
		return nil, fmt.Errorf("kev fetch: %w", err)
	}
	return ParseKEV(data)
}

// ParseKEV parses the CISA KEV JSON (pure, testable): {"vulnerabilities":[{"cveID":"CVE-..."}]}.
// Returns sorted, unique, uppercased CVE IDs.
func ParseKEV(data []byte) ([]string, error) {
	var doc struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("kev parse: %w", err)
	}
	seen := make(map[string]bool, len(doc.Vulnerabilities))
	out := make([]string, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		id := strings.ToUpper(strings.TrimSpace(v.CVEID))
		if !strings.HasPrefix(id, "CVE-") || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out, nil
}
