package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// --- Opt-in network fetcher ---------------------------------------------

// maxFeedBytes caps a downloaded feed so a hostile or misconfigured mirror
// cannot exhaust memory. 256 MiB comfortably holds a full OSV export while
// bounding the blast radius.
const maxFeedBytes = 512 << 20

// HTTPFetcher pulls advisory records from a self-hosted OSV mirror over HTTP(S).
// It expects the URL to return a JSON array of OSV records (the shape a mirror
// of osv.dev exports). It is only constructed when the operator opts into
// network access, keeping the default path fully air-gapped.
type HTTPFetcher struct {
	URL    string
	Client *http.Client
}

// NewHTTPFetcher builds a fetcher with a bounded default timeout.
func NewHTTPFetcher(url string) *HTTPFetcher {
	// 5 minutes: the larger OSV exports (Debian ~67 MiB, npm) don't finish in
	// 60s on a slow link, and MultiFetcher is all-or-nothing, so one slow feed
	// must not fail the whole rebuild.
	return &HTTPFetcher{URL: url, Client: &http.Client{Timeout: 5 * time.Minute}}
}

// Fetch downloads the feed and splits it into individual OSV record documents.
func (f *HTTPFetcher) Fetch(ctx context.Context) ([][]byte, error) {
	if f.URL == "" {
		return nil, fmt.Errorf("no feed URL configured")
	}
	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed %s: HTTP %d", f.URL, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		return nil, err
	}
	// OSV's public exports are zips (PK\x03\x04); a self-hosted mirror may
	// serve a bare JSON array. Support both transparently.
	if len(data) >= 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 3 && data[3] == 4 {
		return unzipOSV(ctx, data)
	}
	// The mirror returns a JSON array of OSV records; hand each back as its own
	// document so the shared normalizer can process them uniformly.
	var records []json.RawMessage
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("feed %s: expected a JSON array of OSV records: %w", f.URL, err)
	}
	out := make([][]byte, 0, len(records))
	for _, r := range records {
		out = append(out, []byte(r))
	}
	return out, nil
}
