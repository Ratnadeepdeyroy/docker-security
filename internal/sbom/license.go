package sbom

import "strings"

// parseLicenseExpr turns a license field into License entries. A single clean
// token (e.g. "MIT", "GPL-2.0-or-later") is recorded as an SPDX id; anything
// compound (containing spaces, operators, or parentheses) is kept verbatim as a
// free-text name so no meaning is invented.
func parseLicenseExpr(s string) []License {
	s = strings.TrimSpace(s)
	if s == "" || s == "unknown" || s == "UNKNOWN" {
		return nil
	}
	if isLicenseID(s) {
		return []License{{ID: s}}
	}
	return []License{{Name: s}}
}

// isLicenseID reports whether s looks like a single SPDX license identifier.
func isLicenseID(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '+':
		default:
			return false
		}
	}
	return true
}
