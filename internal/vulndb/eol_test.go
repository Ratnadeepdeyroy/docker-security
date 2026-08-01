package vulndb

import (
	"testing"
	"time"
)

func TestDistroEOL(t *testing.T) {
	now := time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name, version string
		wantDate      time.Time
		wantEOL       bool
		wantKnown     bool
	}{
		{"alpine", "3.16", date(2024, 5, 23), true, true},  // EOL 2024-05-23
		{"alpine", "3.21", date(2026, 11, 1), false, true}, // EOL 2026-11-01
		{"debian", "10", date(2024, 6, 30), true, true},    // buster LTS ended 2024-06-30
		{"debian", "13", date(2030, 6, 10), false, true},   // trixie
		{"ubuntu", "18.04", date(2023, 5, 31), true, true}, // standard EOL 2023-05-31
		{"rhel", "8.9", date(2029, 5, 31), false, true},    // major-only key match via "rhel 8"
		{"rhel", "7", date(2024, 6, 30), true, true},       // RHEL 7 EOL 2024-06-30
		{"rocky", "9.3", date(2032, 5, 31), false, true},   // Rocky Linux 9 tracks RHEL 9
		{"almalinux", "8.9", date(2029, 5, 31), false, true},
		{"wolfi", "20230201", time.Time{}, false, false}, // rolling release, no EOL table entry
		{"chainguard", "", time.Time{}, false, false},    // rolling release, no EOL table entry
		{"plan9", "4", time.Time{}, false, false},        // unknown distro
	}
	for _, c := range cases {
		d, eol, known := DistroEOL(c.name, c.version, now)
		if eol != c.wantEOL || known != c.wantKnown {
			t.Errorf("%s %s: got eol=%v known=%v want eol=%v known=%v",
				c.name, c.version, eol, known, c.wantEOL, c.wantKnown)
		}
		if !d.Equal(c.wantDate) {
			t.Errorf("%s %s: got date=%v want date=%v", c.name, c.version, d, c.wantDate)
		}
	}
}

// TestDistroEOL_Boundary pins now to the exact EOL instant: a distro is not
// yet "past" end-of-life at the instant it is reached (now.After(eol) is
// false when now == eol), and becomes EOL one nanosecond later.
func TestDistroEOL_Boundary(t *testing.T) {
	eolInstant := date(2024, 5, 23) // alpine 3.16
	d, eol, known := DistroEOL("alpine", "3.16", eolInstant)
	if !known {
		t.Fatal("alpine 3.16 must be a known release")
	}
	if !d.Equal(eolInstant) {
		t.Fatalf("got date=%v want %v", d, eolInstant)
	}
	if eol {
		t.Error("at now == eolDate exactly, eol must be false (not yet past)")
	}
	if _, eolAfter, _ := DistroEOL("alpine", "3.16", eolInstant.Add(time.Nanosecond)); !eolAfter {
		t.Error("one nanosecond after eolDate, eol must be true")
	}
}
