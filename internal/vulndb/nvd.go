package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// --- NVD normalization ----------------------------------------------------
//
// The NVD API 2.0 keys everything off CPE (Common Platform Enumeration)
// applicability statements rather than a package-ecosystem coordinate. There
// is no first-class "npm package X" or "pypi package Y" concept in NVD the
// way there is in OSV/GHSA — a CVE instead lists CPE criteria ("this vendor's
// this product in this version range is affected"). We normalize each
// distinct vendor:product pair into its own Advisory under a synthetic "cpe"
// ecosystem, so NVD records still slot into the same DB/Query machinery as
// every other feed, at the cost of coarser (and sometimes approximate)
// version ranges — see normalizeNVD's documented approximations below.

// nvdCVE is the shape of one NVD API 2.0 `cve` object (the wrapper's
// vulnerabilities[].cve). Only the fields normalizeNVD needs are modeled.
type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		V31 []nvdCVSSMetric `json:"cvssMetricV31"`
		V30 []nvdCVSSMetric `json:"cvssMetricV30"`
		V2  []nvdCVSSMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []nvdCPEMatch `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type nvdCVSSMetric struct {
	Source       string `json:"source"`
	Type         string `json:"type"`
	BaseSeverity string `json:"baseSeverity"`
	CVSSData     struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// normalizeNVD converts one NVD `cve` object into zero or more Advisories, one
// per distinct CPE vendor:product pair referenced by its applicability
// statements. It is pure (no I/O) so it can be exhaustively unit tested
// offline against saved fixtures.
func normalizeNVD(cveDoc []byte) ([]Advisory, error) {
	var cve nvdCVE
	if err := json.Unmarshal(cveDoc, &cve); err != nil {
		return nil, fmt.Errorf("parse nvd cve: %w", err)
	}
	if cve.ID == "" {
		return nil, fmt.Errorf("nvd cve: missing id")
	}

	summary := ""
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			summary = d.Value
			break
		}
	}

	cvss, sev := severityFromNVD(cve)

	var cwes []string
	for _, w := range cve.Weaknesses {
		for _, d := range w.Description {
			if strings.HasPrefix(d.Value, "CWE-") {
				cwes = append(cwes, d.Value)
			}
		}
	}
	cwes = dedupStrings(cwes)

	var refs []string
	for _, r := range cve.References {
		if r.URL != "" {
			refs = append(refs, r.URL)
		}
	}
	refs = dedupStrings(refs)

	// Group ranges by vendor:product.
	type group struct {
		key    string
		ranges []Range
		seen   map[Range]bool
	}
	order := []string{}
	groups := map[string]*group{}

	for _, cfg := range cve.Configurations {
		for _, node := range cfg.Nodes {
			for _, m := range node.CPEMatch {
				if !m.Vulnerable {
					continue
				}
				part, vendor, product, version, ok := parseCPE(m.Criteria)
				if !ok || part == "h" {
					continue
				}
				if vendor == "" || product == "" {
					continue
				}
				key := vendor + ":" + product
				g, exists := groups[key]
				if !exists {
					g = &group{key: key, seen: map[Range]bool{}}
					groups[key] = g
					order = append(order, key)
				}
				r := rangeFromCPEMatch(m, version)
				if !g.seen[r] {
					g.seen[r] = true
					g.ranges = append(g.ranges, r)
				}
			}
		}
	}

	out := make([]Advisory, 0, len(order))
	for _, key := range order {
		g := groups[key]
		adv := Advisory{
			ID:         cve.ID,
			Summary:    summary,
			Ecosystem:  Ecosystem("cpe"),
			Package:    g.key,
			Ranges:     g.ranges,
			Severity:   sev,
			CWEs:       cwes,
			References: append([]string(nil), refs...),
			Source:     "nvd",
			Published:  cve.Published,
			Modified:   cve.LastModified,
		}
		if cvss != nil {
			cp := *cvss
			adv.CVSS = &cp
		}
		out = append(out, adv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Package < out[j].Package })
	return out, nil
}

// rangeFromCPEMatch builds a generic-scheme Range from one cpeMatch entry, per
// the documented NVD-to-Advisory approximations:
//   - Introduced prefers versionStartIncluding, falling back to
//     versionStartExcluding (an approximation: the true lower bound is
//     exclusive, but Range has no separate "introduced-exclusive" concept).
//   - Fixed is versionEndExcluding (the one bound Range models exactly).
//   - LastAffected is versionEndIncluding.
//   - When none of the four bound fields are present and the CPE carries a
//     concrete (non-wildcard) version component, that single version is both
//     the introduced and last-affected bound (an exact-version match).
//   - When the whole range would otherwise be unbounded (wildcard version,
//     no bound fields), Introduced is set to "0" to represent "all versions
//     affected" rather than leaving an ambiguous all-empty Range.
func rangeFromCPEMatch(m nvdCPEMatch, version string) Range {
	r := Range{Scheme: SchemeGeneric}
	switch {
	case m.VersionStartIncluding != "":
		r.Introduced = m.VersionStartIncluding
	case m.VersionStartExcluding != "":
		r.Introduced = m.VersionStartExcluding
	}
	if m.VersionEndExcluding != "" {
		r.Fixed = m.VersionEndExcluding
	}
	if m.VersionEndIncluding != "" {
		r.LastAffected = m.VersionEndIncluding
	}
	if r.Introduced == "" && r.Fixed == "" && r.LastAffected == "" {
		if version != "" && version != "*" && version != "-" {
			r.Introduced = version
			r.LastAffected = version
		} else {
			r.Introduced = "0"
		}
	}
	return r
}

// parseCPE splits a CPE 2.3 formatted string
// ("cpe:2.3:<part>:<vendor>:<product>:<version>:...") into its part, vendor,
// product and version components. CPE escapes literal colons within a
// component with a backslash, so a naive strings.Split on ':' would
// mis-segment criteria like "cpe:2.3:a:cisco:dna_spaces\:_connector:...";
// this walks the string respecting that escaping.
func parseCPE(criteria string) (part, vendor, product, version string, ok bool) {
	fields := splitCPE(criteria)
	if len(fields) < 6 || fields[0] != "cpe" {
		return "", "", "", "", false
	}
	// fields: cpe, 2.3, part, vendor, product, version, update, edition, ...
	part = fields[2]
	vendor = unescapeCPE(fields[3])
	product = unescapeCPE(fields[4])
	version = unescapeCPE(fields[5])
	return part, vendor, product, version, true
}

// splitCPE splits a CPE URI/formatted-string on ':' while treating a
// backslash-escaped colon ("\:") as part of the preceding field rather than a
// separator.
func splitCPE(s string) []string {
	var fields []string
	var cur strings.Builder
	escaped := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case escaped:
			cur.WriteByte(c)
			escaped = false
		case c == '\\':
			cur.WriteByte(c)
			escaped = true
		case c == ':':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	fields = append(fields, cur.String())
	return fields
}

// unescapeCPE removes CPE 2.3's backslash escaping from a single field value.
func unescapeCPE(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			b.WriteByte(s[i])
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// severityFromNVD picks the best available CVSS metric, preferring v3.1 over
// v3.0 over v2, and derives a normalized Severity from it (or from the
// reported baseSeverity word when present).
func severityFromNVD(cve nvdCVE) (*CVSS, Severity) {
	pick := func(metrics []nvdCVSSMetric) (*CVSS, string, bool) {
		if len(metrics) == 0 {
			return nil, "", false
		}
		m := metrics[0]
		c := CVSS{
			Version: m.CVSSData.Version,
			Vector:  m.CVSSData.VectorString,
			Score:   m.CVSSData.BaseScore,
		}
		word := firstNonEmpty(m.CVSSData.BaseSeverity, m.BaseSeverity)
		return &c, word, true
	}

	if c, word, ok := pick(cve.Metrics.V31); ok {
		return c, severityFromWordOrScore(word, c.Score)
	}
	if c, word, ok := pick(cve.Metrics.V30); ok {
		return c, severityFromWordOrScore(word, c.Score)
	}
	if c, word, ok := pick(cve.Metrics.V2); ok {
		return c, severityFromWordOrScore(word, c.Score)
	}
	return nil, SevUnknown
}

func severityFromWordOrScore(word string, score float64) Severity {
	if word != "" {
		if sev := NormalizeSeverityWord(word); sev != SevUnknown {
			return sev
		}
	}
	return SeverityFromScore(score)
}

// --- NVD network fetcher ---------------------------------------------------

const defaultNVDBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// nvdTimeLayout is the timestamp format the NVD API expects for
// lastModStartDate/lastModEndDate query parameters.
const nvdTimeLayout = "2006-01-02T15:04:05.000"

// NVDFetcher retrieves raw per-CVE documents from the live NVD REST API,
// paginating through resultsPerPage-sized pages and rate-limiting itself per
// NVD's published guidance (much slower without an API key).
type NVDFetcher struct {
	APIKey   string
	Client   *http.Client
	Since    time.Time // zero = unbounded (no lastModStartDate/EndDate filter)
	Until    time.Time
	MaxPages int // 0 = unlimited
	PageSize int // capped at 2000; 0 = default 2000
	Sleep    time.Duration
	BaseURL  string
}

// nvdResponse is the shape of the NVD API 2.0 list response.
type nvdResponse struct {
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE json.RawMessage `json:"cve"`
	} `json:"vulnerabilities"`
}

// Fetch implements Fetcher, paginating the NVD CVE API and returning one raw
// `cve` document per CVE across all pages.
func (f NVDFetcher) Fetch(ctx context.Context) ([][]byte, error) {
	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}
	baseURL := f.BaseURL
	if baseURL == "" {
		baseURL = defaultNVDBaseURL
	}
	pageSize := f.PageSize
	if pageSize <= 0 {
		pageSize = 2000
	}
	if pageSize > 2000 {
		pageSize = 2000
	}
	sleep := f.Sleep
	if sleep == 0 {
		if f.APIKey == "" {
			sleep = 6 * time.Second
		} else {
			sleep = 700 * time.Millisecond
		}
	}

	var out [][]byte
	startIndex := 0
	page := 0
	for {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		q := url.Values{}
		q.Set("resultsPerPage", fmt.Sprintf("%d", pageSize))
		q.Set("startIndex", fmt.Sprintf("%d", startIndex))
		if !f.Since.IsZero() {
			// NVD requires lastModStartDate and lastModEndDate together and a
			// window <= 120 days. Default the end to "now" when the caller left
			// Until zero (the common incremental case), and clamp the start so
			// the window never exceeds NVD's 120-day maximum.
			until := f.Until
			if until.IsZero() {
				until = time.Now().UTC()
			}
			start := f.Since
			if until.Sub(start) > 120*24*time.Hour {
				start = until.Add(-120 * 24 * time.Hour)
			}
			q.Set("lastModStartDate", start.UTC().Format(nvdTimeLayout))
			q.Set("lastModEndDate", until.UTC().Format(nvdTimeLayout))
		}
		reqURL := baseURL + "?" + q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
		if err != nil {
			return nil, fmt.Errorf("nvd fetch: build request: %w", err)
		}
		if f.APIKey != "" {
			req.Header.Set("apiKey", f.APIKey)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("nvd fetch: %w", err)
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("nvd fetch: unexpected status %d for %s", resp.StatusCode, reqURL)
		}
		if readErr != nil {
			return nil, fmt.Errorf("nvd fetch: read response: %w", readErr)
		}

		var parsed nvdResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("nvd fetch: parse response: %w", err)
		}
		for _, v := range parsed.Vulnerabilities {
			out = append(out, []byte(v.CVE))
		}

		startIndex += pageSize
		page++
		if startIndex >= parsed.TotalResults {
			break
		}
		if f.MaxPages > 0 && page >= f.MaxPages {
			break
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleep):
		}
	}
	return out, nil
}

// --- NVD database build ----------------------------------------------------

// UpdateNVD builds a DB from an NVD Fetcher, normalizing every fetched `cve`
// document and merging duplicate CVEs across (ecosystem, package) the same
// way every other feed does (see mergeByAlias). A per-document normalization
// failure is counted in SkippedRecords rather than aborting the whole update.
func UpdateNVD(ctx context.Context, fetcher Fetcher, source string, now time.Time, epss map[string]float64, kev []string) (*DB, error) {
	docs, err := fetcher.Fetch(ctx)
	if err != nil {
		return nil, fmt.Errorf("nvd update: fetch: %w", err)
	}

	var advisories []Advisory
	var skipped int
	for _, doc := range docs {
		adv, err := normalizeNVD(doc)
		if err != nil {
			skipped++
			continue
		}
		advisories = append(advisories, adv...)
	}
	merged := mergeByAlias(advisories)

	db := &DB{
		Schema:         currentSchema,
		BuiltAt:        now.UTC(),
		Source:         source,
		Advisories:     merged,
		EPSS:           epss,
		KEV:            kev,
		SkippedRecords: skipped,
	}
	db.index()
	return db, nil
}
