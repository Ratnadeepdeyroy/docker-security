package store

import (
	"sort"
	"strings"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Blast-radius query --------------------------------------------------

// ComponentQuery selects scans by an inventoried component. This is the
// zero-day workflow: "advisory just dropped for openssl < 3.0.7 — where is it?".
type ComponentQuery struct {
	Name    string // component name (case-insensitive); empty matches any
	Version string // exact version; empty matches any version
	PURL    string // exact purl; empty ignored
	// LatestPerImage keeps only the most recent scan per image, so a component
	// removed in a newer scan does not keep flagging the image.
	LatestPerImage bool
}

// ComponentMatch is one image found to contain the queried component.
type ComponentMatch struct {
	Image      string    `json:"image"`
	Digest     string    `json:"digest,omitempty"`
	Version    string    `json:"version"`
	PURL       string    `json:"purl,omitempty"`
	ScanID     string    `json:"scan_id"`
	RecordedAt time.Time `json:"recorded_at"`
	Owner      string    `json:"owner,omitempty"`
}

// QueryComponent answers the blast-radius question: which stored images contain
// the queried component (optionally pinned to a version). Results are sorted by
// image then version then recorded time for a stable, human-scannable order.
func (s *Store) QueryComponent(q ComponentQuery) []ComponentMatch {
	name := strings.ToLower(strings.TrimSpace(q.Name))
	version := strings.TrimSpace(q.Version)

	s.mu.RLock()
	scans := make([]*Scan, 0, len(s.scans))
	for _, sc := range s.scans {
		scans = append(scans, sc)
	}
	s.mu.RUnlock()

	if q.LatestPerImage {
		scans = latestPerImage(scans)
	}

	var out []ComponentMatch
	for _, sc := range scans {
		for _, c := range sc.Components {
			if name != "" && c.Name != name {
				continue
			}
			if version != "" && c.Version != version {
				continue
			}
			if q.PURL != "" && c.PURL != q.PURL {
				continue
			}
			out = append(out, ComponentMatch{
				Image:      sc.Image,
				Digest:     sc.Digest,
				Version:    c.Version,
				PURL:       c.PURL,
				ScanID:     sc.ID,
				RecordedAt: sc.RecordedAt,
				Owner:      sc.Labels["owner"],
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Image != out[j].Image {
			return out[i].Image < out[j].Image
		}
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].RecordedAt.After(out[j].RecordedAt)
	})
	return out
}

// latestPerImage keeps the newest scan for each distinct image.
func latestPerImage(scans []*Scan) []*Scan {
	best := map[string]*Scan{}
	for _, sc := range scans {
		cur, ok := best[sc.Image]
		if !ok || sc.RecordedAt.After(cur.RecordedAt) || (sc.RecordedAt.Equal(cur.RecordedAt) && sc.ID > cur.ID) {
			best[sc.Image] = sc
		}
	}
	out := make([]*Scan, 0, len(best))
	for _, sc := range best {
		out = append(out, sc)
	}
	sortScans(out)
	return out
}

// --- Findings query ------------------------------------------------------

// FindingQuery filters findings across the whole store. Zero-valued fields are
// ignored, so an empty query returns everything.
type FindingQuery struct {
	Image       string
	Module      string
	RuleID      string
	Owner       string
	MinSeverity engine.Severity
	Since       time.Time
	Until       time.Time
}

// FindingHit is a finding plus the scan context needed to act on it.
type FindingHit struct {
	Image      string         `json:"image"`
	ScanID     string         `json:"scan_id"`
	RecordedAt time.Time      `json:"recorded_at"`
	Owner      string         `json:"owner,omitempty"`
	Finding    engine.Finding `json:"finding"`
}

// QueryFindings returns findings matching the filter, most-severe first, then by
// image and rule id. Attribution (image, owner, scan) travels with each hit so a
// caller can route it without a second lookup.
func (s *Store) QueryFindings(q FindingQuery) []FindingHit {
	s.mu.RLock()
	scans := make([]*Scan, 0, len(s.scans))
	for _, sc := range s.scans {
		scans = append(scans, sc)
	}
	s.mu.RUnlock()

	var out []FindingHit
	for _, sc := range scans {
		if q.Image != "" && sc.Image != q.Image {
			continue
		}
		if q.Owner != "" && sc.Labels["owner"] != q.Owner {
			continue
		}
		if !q.Since.IsZero() && sc.RecordedAt.Before(q.Since) {
			continue
		}
		if !q.Until.IsZero() && sc.RecordedAt.After(q.Until) {
			continue
		}
		if sc.Report == nil {
			continue
		}
		for _, f := range sc.Report.Findings {
			if q.Module != "" && f.Module != q.Module {
				continue
			}
			if q.RuleID != "" && f.RuleID != q.RuleID {
				continue
			}
			if q.MinSeverity != engine.SeverityUnknown && f.Severity < q.MinSeverity {
				continue
			}
			out = append(out, FindingHit{
				Image:      sc.Image,
				ScanID:     sc.ID,
				RecordedAt: sc.RecordedAt,
				Owner:      sc.Labels["owner"],
				Finding:    f,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Finding.Severity != out[j].Finding.Severity {
			return out[i].Finding.Severity > out[j].Finding.Severity
		}
		if out[i].Image != out[j].Image {
			return out[i].Image < out[j].Image
		}
		return out[i].Finding.RuleID < out[j].Finding.RuleID
	})
	return out
}

// --- Inventory & trends --------------------------------------------------

// ImageSummary is one row of the inventory view: an image, its latest scan's
// severity posture, and how much we know about it.
type ImageSummary struct {
	Image       string         `json:"image"`
	Digest      string         `json:"digest,omitempty"`
	Owner       string         `json:"owner,omitempty"`
	LastScanned time.Time      `json:"last_scanned"`
	Scans       int            `json:"scans"`
	Components  int            `json:"components"`
	Counts      map[string]int `json:"counts"` // severity name → count (latest scan)
	Total       int            `json:"total"`
}

// Inventory returns one summary per distinct image, using each image's most
// recent scan for the severity posture. Sorted by descending critical+high
// count then image name, so the riskiest images sort to the top.
func (s *Store) Inventory() []ImageSummary {
	s.mu.RLock()
	byImage := map[string][]*Scan{}
	for _, sc := range s.scans {
		byImage[sc.Image] = append(byImage[sc.Image], sc)
	}
	s.mu.RUnlock()

	var out []ImageSummary
	for image, scans := range byImage {
		sortScans(scans)
		latest := scans[0]
		counts := severityCounts(latest.Report)
		out = append(out, ImageSummary{
			Image:       image,
			Digest:      latest.Digest,
			Owner:       latest.Labels["owner"],
			LastScanned: latest.RecordedAt,
			Scans:       len(scans),
			Components:  len(latest.Components),
			Counts:      counts,
			Total:       total(counts),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		ri := out[i].Counts["CRITICAL"] + out[i].Counts["HIGH"]
		rj := out[j].Counts["CRITICAL"] + out[j].Counts["HIGH"]
		if ri != rj {
			return ri > rj
		}
		return out[i].Image < out[j].Image
	})
	return out
}

// TrendPoint is the severity posture of one image at one point in time.
type TrendPoint struct {
	ScanID     string         `json:"scan_id"`
	RecordedAt time.Time      `json:"recorded_at"`
	Counts     map[string]int `json:"counts"`
	Total      int            `json:"total"`
}

// Trends returns the time-ordered posture for an image (oldest first) so a UI
// can plot whether findings are climbing or being burned down. An empty image
// aggregates every scan chronologically.
func (s *Store) Trends(image string) []TrendPoint {
	s.mu.RLock()
	var scans []*Scan
	for _, sc := range s.scans {
		if image == "" || sc.Image == image {
			scans = append(scans, sc)
		}
	}
	s.mu.RUnlock()

	sort.SliceStable(scans, func(i, j int) bool {
		if !scans[i].RecordedAt.Equal(scans[j].RecordedAt) {
			return scans[i].RecordedAt.Before(scans[j].RecordedAt)
		}
		return scans[i].ID < scans[j].ID
	})

	out := make([]TrendPoint, 0, len(scans))
	for _, sc := range scans {
		counts := severityCounts(sc.Report)
		out = append(out, TrendPoint{
			ScanID:     sc.ID,
			RecordedAt: sc.RecordedAt,
			Counts:     counts,
			Total:      total(counts),
		})
	}
	return out
}

// severityCounts tallies a report's findings by severity name. Always returns a
// map with all five levels present (zeroed) so JSON output is shape-stable.
func severityCounts(r *engine.Report) map[string]int {
	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
	if r == nil {
		return counts
	}
	for _, f := range r.Findings {
		counts[f.Severity.String()]++
	}
	return counts
}

func total(counts map[string]int) int {
	n := 0
	for _, v := range counts {
		n += v
	}
	return n
}
