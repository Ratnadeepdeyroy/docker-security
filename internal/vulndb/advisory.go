// Package vulndb is the offline, normalized advisory store behind the vuln
// module. It defines a single internal advisory schema that every feed (NVD,
// GHSA, OSV, distro security trackers) normalizes *into*, so vulnerability
// matching never depends on a feed's quirks. The store is a plain JSON file —
// no external database engine — that loads deterministically, carries a build
// timestamp for staleness reporting, and ships with an embedded snapshot so the
// tool works fully air-gapped out of the box.
//
// Version comparison is the part of a scanner that "lives or dies" on accuracy:
// ecosystems disagree on version semantics (Debian epochs, RPM evr, Alpine apk
// suffixes, Go pseudo-versions, PEP 440, semver pre-releases, Maven qualifiers),
// so comparison is delegated per-scheme rather than assuming one ordering — the
// classic source of false matches. See version*.go.
package vulndb

import "strings"

// --- Normalized advisory schema -----------------------------------------

// Ecosystem is the feed namespace an advisory applies to. For OS packages it is
// the distro id (alpine, debian, ubuntu, rhel, …); for language dependencies it
// is the package ecosystem (npm, pypi, go, maven, cargo, rubygems, composer,
// nuget). It selects *which* advisories apply to a component; the VersionScheme
// (see scheme) selects *how* versions within them are compared.
type Ecosystem string

// VersionScheme names a per-ecosystem version ordering. Matching dispatches on
// it so, e.g., a Debian epoch never gets compared with semver rules.
type VersionScheme string

const (
	SchemeSemver  VersionScheme = "semver"
	SchemeDeb     VersionScheme = "deb"
	SchemeRPM     VersionScheme = "rpm"
	SchemeAPK     VersionScheme = "apk"
	SchemePEP440  VersionScheme = "pep440"
	SchemeGo      VersionScheme = "go"
	SchemeMaven   VersionScheme = "maven"
	SchemeGem     VersionScheme = "gem"
	SchemeGeneric VersionScheme = "generic"
)

// scheme maps an ecosystem to its default version-comparison scheme. An
// advisory Range may override this (OSV distinguishes SEMVER vs ECOSYSTEM
// ranges), but the ecosystem default is correct for the overwhelming majority.
func scheme(e Ecosystem) VersionScheme {
	switch strings.ToLower(string(e)) {
	case "alpine", "wolfi", "chainguard":
		return SchemeAPK
	case "debian", "ubuntu":
		return SchemeDeb
	case "rhel", "redhat", "centos", "rocky", "almalinux", "alma", "amazon", "amzn",
		"fedora", "opensuse", "suse", "sles", "photon", "mariner":
		return SchemeRPM
	case "npm", "cargo", "crates.io", "composer", "packagist", "nuget":
		return SchemeSemver
	case "pypi", "python":
		return SchemePEP440
	case "go", "golang":
		return SchemeGo
	case "maven":
		return SchemeMaven
	case "rubygems", "gem":
		return SchemeGem
	default:
		return SchemeGeneric
	}
}

// Severity is a normalized qualitative risk level. Feeds report severity in
// incompatible ways (NVD bands, GHSA labels, distro-specific words); they all
// normalize into this small ordered set.
type Severity string

const (
	SevCritical   Severity = "critical"
	SevHigh       Severity = "high"
	SevMedium     Severity = "medium"
	SevLow        Severity = "low"
	SevNegligible Severity = "negligible"
	SevUnknown    Severity = "unknown"
)

// Rank returns an ascending numeric order for a severity, so callers can sort
// or gate without a switch. Higher is worse.
func (s Severity) Rank() int {
	switch s {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevNegligible:
		return 1
	default:
		return 0
	}
}

// CVSS carries a single CVSS metric as reported by a feed.
type CVSS struct {
	Version string  `json:"version,omitempty"` // "2.0", "3.0", "3.1", "4.0"
	Vector  string  `json:"vector,omitempty"`
	Score   float64 `json:"score,omitempty"`
}

// Range is one affected version interval for a package. Semantics:
//   - Introduced=="" or "0" means "from the beginning of time".
//   - Fixed is the first version that is NOT affected (exclusive upper bound).
//     A non-empty Fixed also tells us the vulnerability is fixable and where.
//   - LastAffected is an inclusive upper bound used when there is no fix
//     (open range with a known last-vulnerable version).
//
// An advisory may carry several ranges (multiple affected branches).
type Range struct {
	Scheme       VersionScheme `json:"scheme,omitempty"` // override; empty = ecosystem default
	Introduced   string        `json:"introduced,omitempty"`
	Fixed        string        `json:"fixed,omitempty"`
	LastAffected string        `json:"last_affected,omitempty"`
}

// Advisory is the single normalized record every feed maps into. One Advisory
// describes one (ecosystem, package) pair; a feed entry that affects several
// packages normalizes into several Advisories sharing an ID/aliases.
type Advisory struct {
	ID        string    `json:"id"`                // primary id, e.g. CVE-2023-45853 / GHSA-xxxx
	Aliases   []string  `json:"aliases,omitempty"` // other ids used for de-dup and enrichment lookups
	Summary   string    `json:"summary,omitempty"`
	Ecosystem Ecosystem `json:"ecosystem"`
	Package   string    `json:"package"`
	Ranges    []Range   `json:"ranges"`
	Severity  Severity  `json:"severity,omitempty"`
	CVSS      *CVSS     `json:"cvss,omitempty"`
	CWEs      []string  `json:"cwes,omitempty"`
	// Symbols lists the specific vulnerable symbols/functions when a feed
	// declares them (as OSV's ecosystem_specific imports do). It powers
	// symbol-level reachability: an advisory with symbols is only "reached" when
	// one of them is actually used. Empty means "unknown", treated as reachable.
	Symbols    []string `json:"symbols,omitempty"`
	References []string `json:"references,omitempty"`
	Source     string   `json:"source,omitempty"`    // feed name: nvd/ghsa/osv/distro
	Published  string   `json:"published,omitempty"` // kept verbatim; never sampled from the clock
	Modified   string   `json:"modified,omitempty"`
}

// ids returns the advisory's primary id followed by its aliases, for
// enrichment lookups (EPSS/KEV are keyed by CVE, which may be an alias).
func (a Advisory) ids() []string {
	out := make([]string, 0, len(a.Aliases)+1)
	if a.ID != "" {
		out = append(out, a.ID)
	}
	out = append(out, a.Aliases...)
	return out
}

// FixedVersion returns the smallest fixed version across the advisory's ranges,
// or "" if none is known (an unfixed vulnerability). It is the concrete upgrade
// target an operator — or an AI agent — should move to.
func (a Advisory) FixedVersion(sch VersionScheme) string {
	best := ""
	for _, r := range a.Ranges {
		if r.Fixed == "" {
			continue
		}
		if best == "" || Compare(rangeScheme(r, sch), r.Fixed, best) < 0 {
			best = r.Fixed
		}
	}
	return best
}
