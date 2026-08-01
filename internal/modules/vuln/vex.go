package vuln

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// --- VEX ingestion -------------------------------------------------------
//
// VEX (Vulnerability Exploitability eXchange) lets a supplier or operator assert
// that a CVE present in the SBOM is not actually exploitable, so the scanner can
// suppress it. We ingest the OpenVEX shape (the de-facto standard) and honor
// not_affected/fixed statements. This is the difference between a report a human
// will read and a wall of inherited-CVE noise they will ignore.

type vexStatus string

const (
	vexNotAffected        vexStatus = "not_affected"
	vexAffected           vexStatus = "affected"
	vexFixed              vexStatus = "fixed"
	vexUnderInvestigation vexStatus = "under_investigation"
)

// VEXStatement is a normalized single VEX assertion.
type VEXStatement struct {
	Vuln          string   // CVE/GHSA id the statement is about
	Products      []string // product identifiers (PURLs); empty = applies to all
	Status        vexStatus
	Justification string
}

// ParseVEX parses an OpenVEX document into normalized statements. It tolerates
// both the object and string spellings OpenVEX allows for vulnerability and
// product fields.
func ParseVEX(data []byte) ([]VEXStatement, error) {
	var doc struct {
		Statements []struct {
			Vulnerability json.RawMessage `json:"vulnerability"`
			Products      json.RawMessage `json:"products"`
			Status        string          `json:"status"`
			Justification string          `json:"justification"`
		} `json:"statements"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse openvex: %w", err)
	}
	out := make([]VEXStatement, 0, len(doc.Statements))
	for _, s := range doc.Statements {
		out = append(out, VEXStatement{
			Vuln:          vexName(s.Vulnerability),
			Products:      vexProducts(s.Products),
			Status:        vexStatus(strings.ToLower(strings.TrimSpace(s.Status))),
			Justification: s.Justification,
		})
	}
	return out, nil
}

// LoadVEXFile reads and parses an OpenVEX document from disk.
func LoadVEXFile(path string) ([]VEXStatement, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vex %q: %w", path, err)
	}
	return ParseVEX(data)
}

// matchVEX finds the first VEX statement covering any of ids for the given
// product. A statement with no products applies to every product.
func matchVEX(statements []VEXStatement, ids []string, purl string) (vexStatus, string, bool) {
	for _, st := range statements {
		if !idMatches(st.Vuln, ids) {
			continue
		}
		if !productMatches(st.Products, purl) {
			continue
		}
		return st.Status, st.Justification, true
	}
	return "", "", false
}

func productMatches(products []string, purl string) bool {
	if len(products) == 0 {
		return true // statement applies to all products
	}
	for _, p := range products {
		if p == "*" || p == purl {
			return true
		}
		// Match a product that names the component with extra qualifiers/subpath.
		if purl != "" && strings.HasPrefix(purl, p) {
			return true
		}
	}
	return false
}

// vexName extracts a vulnerability name from either {"name":..}/{"@id":..} or a
// bare string.
func vexName(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var obj struct {
		Name string `json:"name"`
		ID   string `json:"@id"`
	}
	if json.Unmarshal(raw, &obj) == nil {
		if obj.Name != "" {
			return obj.Name
		}
		return obj.ID
	}
	return ""
}

// vexProducts extracts product identifiers from an array of strings or objects
// carrying an "@id".
func vexProducts(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var strs []string
	if json.Unmarshal(raw, &strs) == nil {
		return strs
	}
	var objs []struct {
		ID string `json:"@id"`
	}
	if json.Unmarshal(raw, &objs) == nil {
		out := make([]string, 0, len(objs))
		for _, o := range objs {
			if o.ID != "" {
				out = append(out, o.ID)
			}
		}
		return out
	}
	return nil
}

// --- Waivers / allowlist -------------------------------------------------
//
// A waiver is an operator's explicit, justified decision to accept a specific
// risk for a bounded time. Unlike a blanket ignore, it demands a reason and an
// expiry, so accepted risk cannot silently become permanent — an expired waiver
// stops suppressing and the finding resurfaces.

// Waiver is an allowlist entry.
type Waiver struct {
	Vulnerability string    // CVE/GHSA id, or "*"/"" for any
	Package       string    // package name, or "*"/"" for any
	Reason        string    // required justification (audit trail)
	Expires       time.Time // zero = never expires
}

// LoadWaiversFile reads a JSON array of waivers. Expiry is an RFC 3339 string.
func LoadWaiversFile(path string) ([]Waiver, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read waivers %q: %w", path, err)
	}
	var raw []struct {
		Vulnerability string `json:"vulnerability"`
		Package       string `json:"package"`
		Reason        string `json:"reason"`
		Expires       string `json:"expires"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse waivers %q: %w", path, err)
	}
	out := make([]Waiver, 0, len(raw))
	for _, r := range raw {
		w := Waiver{Vulnerability: r.Vulnerability, Package: r.Package, Reason: r.Reason}
		if r.Expires != "" {
			if ts, err := time.Parse(time.RFC3339, r.Expires); err == nil {
				w.Expires = ts
			}
		}
		out = append(out, w)
	}
	return out, nil
}

// matchWaiver returns the first active waiver covering the vulnerability and
// package. An expired waiver (relative to an injected now) does not match, so
// the finding is reported again.
func matchWaiver(waivers []Waiver, ids []string, pkg string, now time.Time) (Waiver, bool) {
	for _, w := range waivers {
		if !waiverVulnMatches(w.Vulnerability, ids) {
			continue
		}
		if !waiverPkgMatches(w.Package, pkg) {
			continue
		}
		if waiverExpired(w, now) {
			continue
		}
		return w, true
	}
	return Waiver{}, false
}

func waiverVulnMatches(pattern string, ids []string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	return idMatches(pattern, ids)
}

func waiverPkgMatches(pattern, pkg string) bool {
	return pattern == "" || pattern == "*" || pattern == pkg
}

// waiverExpired reports whether a waiver has lapsed. With no expiry it never
// lapses; with no injected clock (now zero) expiry cannot be evaluated, so the
// waiver is treated as active to keep analysis deterministic.
func waiverExpired(w Waiver, now time.Time) bool {
	if w.Expires.IsZero() || now.IsZero() {
		return false
	}
	return now.After(w.Expires)
}

// idMatches reports whether pattern equals any of ids, case-insensitively.
func idMatches(pattern string, ids []string) bool {
	p := strings.ToUpper(strings.TrimSpace(pattern))
	for _, id := range ids {
		if strings.ToUpper(id) == p {
			return true
		}
	}
	return false
}
