package vulndb

import (
	"strings"
	"time"
)

// eolDates maps "distro version" to its end-of-life date. After this date the
// distro publishes no security advisories, so an empty vuln result is
// meaningless — the image must be flagged. Sources: endoflife.date and the
// distros' published schedules. Extend by appending; never edit past entries.
//
// Coverage: alpine, debian, ubuntu, centos, rhel, rocky (Rocky Linux), and
// almalinux all have entries. wolfi and chainguard are intentionally absent —
// both are rolling-release distros with no fixed end-of-life date, so
// DistroEOL correctly (and permanently) returns known=false for them via the
// normal "not in the table" fallback rather than a fabricated date.
var eolDates = map[string]time.Time{
	"alpine 3.14": date(2023, 5, 1), "alpine 3.15": date(2023, 11, 1),
	"alpine 3.16": date(2024, 5, 23), "alpine 3.17": date(2024, 11, 22),
	"alpine 3.18": date(2025, 5, 9), "alpine 3.19": date(2025, 11, 1),
	"alpine 3.20": date(2026, 4, 1), "alpine 3.21": date(2026, 11, 1),
	"alpine 3.22": date(2027, 5, 1),
	"debian 9":    date(2022, 6, 30), "debian 10": date(2024, 6, 30),
	"debian 11": date(2026, 8, 31), "debian 12": date(2028, 6, 10),
	"debian 13":    date(2030, 6, 10),
	"ubuntu 16.04": date(2021, 4, 30), "ubuntu 18.04": date(2023, 5, 31),
	"ubuntu 20.04": date(2025, 5, 31), "ubuntu 22.04": date(2027, 6, 1),
	"ubuntu 24.04": date(2029, 5, 31),
	"centos 7":     date(2024, 6, 30), "centos 8": date(2021, 12, 31),
	// RHEL tracks major-version-only EOL (its published lifecycle is per major
	// release, not per minor point release), matching the centos/debian style.
	"rhel 7": date(2024, 6, 30), "rhel 8": date(2029, 5, 31),
	"rhel 9": date(2032, 5, 31),
	// Rocky Linux and AlmaLinux are RHEL-compatible rebuilds and track RHEL's
	// published lifecycle for the corresponding major version.
	"rocky 8": date(2029, 5, 31), "rocky 9": date(2032, 5, 31),
	"almalinux 8": date(2029, 5, 31), "almalinux 9": date(2032, 5, 31),
}

func date(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// DistroEOL reports whether the given distro release is past end-of-life at
// `now`. known=false means the release is not in the table (no claim made).
// Version matching uses the major (debian/centos) or major.minor
// (alpine/ubuntu) prefix so "3.16.9" matches "alpine 3.16".
func DistroEOL(name, version string, now time.Time) (time.Time, bool, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	parts := strings.Split(version, ".")
	keys := []string{}
	if len(parts) >= 2 {
		keys = append(keys, name+" "+parts[0]+"."+parts[1])
	}
	keys = append(keys, name+" "+parts[0])
	for _, k := range keys {
		if d, ok := eolDates[k]; ok {
			return d, now.After(d), true
		}
	}
	return time.Time{}, false, false
}
