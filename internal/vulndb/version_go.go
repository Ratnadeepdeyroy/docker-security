package vulndb

import "strings"

// --- Go module version comparison ---------------------------------------

// compareGo compares Go module versions. Go versions are valid SemVer with a
// leading 'v', so the base ordering is semver; two extra rules matter for
// matching:
//
//   - "+incompatible" is a build-tag-like suffix that does not affect ordering.
//   - Pseudo-versions ("v0.0.0-20230101000000-abcdef123456") encode a commit
//     timestamp in a fixed-width field, so they order correctly under semver's
//     pre-release rules (the timestamp compares lexically = chronologically).
//
// Delegating to compareSemver keeps this correct without a second version
// engine.
func compareGo(a, b string) int {
	return compareSemver(normalizeGo(a), normalizeGo(b))
}

func normalizeGo(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(v, "+incompatible")
	return v
}
