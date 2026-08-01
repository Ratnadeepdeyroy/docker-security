package store

import (
	"flag"
	"testing"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// update regenerates golden files when set: go test ./internal/store -update.
var update = flag.Bool("update", false, "regenerate golden files")

// at builds a fixed timestamp so tests never touch the wall clock.
func at(day int) time.Time {
	return time.Date(2026, 1, day, 0, 0, 0, 0, time.UTC)
}

// scan is a compact constructor for test fixtures.
func scan(image string, day int, comps []Component, findings ...engine.Finding) *Scan {
	return &Scan{
		Image:      image,
		RecordedAt: at(day),
		Labels:     map[string]string{"owner": "team-" + image[:1]},
		Report:     &engine.Report{Target: image, Findings: findings},
		Components: comps,
	}
}

func f(rule string, sev engine.Severity) engine.Finding {
	return engine.Finding{RuleID: rule, Module: "test", Severity: sev, Title: rule}
}

// seed populates a memory store with three images across two days. "api" is
// scanned twice (day 1 clean-ish, day 3 worse) to exercise trends and
// latest-per-image.
func seed(t *testing.T) *Store {
	t.Helper()
	s := NewMemory()
	put := func(sc *Scan) {
		if _, err := s.Put(sc); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	put(scan("api", 1,
		[]Component{{Name: "openssl", Version: "3.0.1"}, {Name: "zlib", Version: "1.2.13"}},
		f("DS-RAT-VULN-001", engine.SeverityMedium)))
	put(scan("api", 3,
		[]Component{{Name: "OpenSSL", Version: "3.0.7"}, {Name: "zlib", Version: "1.2.13"}},
		f("DS-RAT-VULN-002", engine.SeverityCritical), f("DS-RAT-DF-001", engine.SeverityHigh)))
	put(scan("web", 2,
		[]Component{{Name: "openssl", Version: "3.0.1"}, {Name: "nginx", Version: "1.25.0"}},
		f("DS-RAT-DF-002", engine.SeverityLow)))
	return s
}

func TestBlastRadius_VersionPinnedFindsAffectedImages(t *testing.T) {
	s := seed(t)
	// Zero-day in openssl 3.0.1: which stored images shipped exactly that?
	got := s.QueryComponent(ComponentQuery{Name: "openssl", Version: "3.0.1"})
	if len(got) != 2 {
		t.Fatalf("want 2 matches for openssl 3.0.1, got %d: %+v", len(got), got)
	}
	// Sorted by image: api (day 1) then web (day 2).
	if got[0].Image != "api" || got[1].Image != "web" {
		t.Errorf("unexpected order: %s, %s", got[0].Image, got[1].Image)
	}
}

func TestBlastRadius_CaseInsensitiveNameAnyVersion(t *testing.T) {
	s := seed(t)
	// "OpenSSL" was stored on the api day-3 scan; matching must be case-insensitive
	// and, with no version, return every openssl across every scan.
	got := s.QueryComponent(ComponentQuery{Name: "OPENSSL"})
	if len(got) != 3 {
		t.Fatalf("want 3 openssl matches across all scans, got %d: %+v", len(got), got)
	}
}

func TestBlastRadius_LatestPerImageDropsSupersededScan(t *testing.T) {
	s := seed(t)
	// api upgraded openssl 3.0.1 → 3.0.7 on day 3. With LatestPerImage, the day-1
	// vulnerable record must not be reported for api.
	got := s.QueryComponent(ComponentQuery{Name: "openssl", Version: "3.0.1", LatestPerImage: true})
	for _, m := range got {
		if m.Image == "api" {
			t.Errorf("api still reported for openssl 3.0.1 despite upgrade: %+v", m)
		}
	}
	if len(got) != 1 || got[0].Image != "web" {
		t.Fatalf("want only web, got %+v", got)
	}
}

func TestQueryFindings_SeverityAndModuleFilters(t *testing.T) {
	s := seed(t)
	crit := s.QueryFindings(FindingQuery{MinSeverity: engine.SeverityHigh})
	if len(crit) != 2 {
		t.Fatalf("want 2 findings >= HIGH, got %d", len(crit))
	}
	// Most-severe-first ordering.
	if crit[0].Finding.Severity != engine.SeverityCritical {
		t.Errorf("want CRITICAL first, got %s", crit[0].Finding.Severity)
	}
	// Attribution travels with the hit.
	if crit[0].Image != "api" || crit[0].Owner != "team-a" {
		t.Errorf("bad attribution: image=%s owner=%s", crit[0].Image, crit[0].Owner)
	}
}

func TestQueryFindings_OwnerFilter(t *testing.T) {
	s := seed(t)
	got := s.QueryFindings(FindingQuery{Owner: "team-w"})
	if len(got) != 1 || got[0].Image != "web" {
		t.Fatalf("owner filter failed: %+v", got)
	}
}

func TestInventory_RiskiestImageSortsFirst(t *testing.T) {
	s := seed(t)
	inv := s.Inventory()
	if len(inv) != 2 {
		t.Fatalf("want 2 images, got %d", len(inv))
	}
	// api's latest scan has CRITICAL+HIGH; web has only LOW.
	if inv[0].Image != "api" {
		t.Errorf("want api first (riskiest), got %s", inv[0].Image)
	}
	if inv[0].Scans != 2 {
		t.Errorf("api should have 2 scans, got %d", inv[0].Scans)
	}
	if inv[0].Counts["CRITICAL"] != 1 || inv[0].Counts["HIGH"] != 1 {
		t.Errorf("api latest counts wrong: %+v", inv[0].Counts)
	}
}

func TestTrends_ChronologicalPerImage(t *testing.T) {
	s := seed(t)
	tr := s.Trends("api")
	if len(tr) != 2 {
		t.Fatalf("want 2 trend points for api, got %d", len(tr))
	}
	if !tr[0].RecordedAt.Before(tr[1].RecordedAt) {
		t.Errorf("trends not chronological: %v then %v", tr[0].RecordedAt, tr[1].RecordedAt)
	}
	// Posture worsened: day 1 total < day 3 total.
	if !(tr[0].Total < tr[1].Total) {
		t.Errorf("expected worsening trend, got %d then %d", tr[0].Total, tr[1].Total)
	}
}

func TestPut_DeterministicIDAndIdempotentOverwrite(t *testing.T) {
	a := scan("api", 1, nil, f("DS-RAT-X-1", engine.SeverityLow))
	b := scan("api", 1, nil, f("DS-RAT-X-1", engine.SeverityLow))
	id1, _ := NewMemory().Put(a)
	id2, _ := NewMemory().Put(b)
	if id1 != id2 {
		t.Fatalf("same scan yielded different ids: %s vs %s", id1, id2)
	}
	// Re-putting the same identity overwrites rather than growing the store.
	s := NewMemory()
	s.Put(a)
	s.Put(b)
	if s.Len() != 1 {
		t.Errorf("idempotent re-put grew store to %d", s.Len())
	}
}

func TestPut_RejectsNilAndImagelessScans(t *testing.T) {
	s := NewMemory()
	if _, err := s.Put(nil); err == nil {
		t.Error("expected error for nil scan")
	}
	if _, err := s.Put(&Scan{RecordedAt: at(1)}); err == nil {
		t.Error("expected error for image-less scan")
	}
}
