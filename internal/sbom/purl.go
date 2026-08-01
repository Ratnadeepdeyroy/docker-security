package sbom

import (
	"sort"
	"strings"
)

// purl builds a Package URL string per the purl specification. Namespace may be
// empty; qualifiers are emitted sorted by key for determinism. Path separators
// inside namespace (e.g. a Go module path) are preserved.
func purl(typ, namespace, name, version string, qualifiers map[string]string) string {
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(typ)
	if namespace != "" {
		b.WriteString("/")
		b.WriteString(escapeNamespace(namespace))
	}
	b.WriteString("/")
	b.WriteString(escapeSegment(name))
	if version != "" {
		b.WriteString("@")
		b.WriteString(escapeVersion(version))
	}
	if len(qualifiers) > 0 {
		keys := make([]string, 0, len(qualifiers))
		for k := range qualifiers {
			if qualifiers[k] != "" {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		if len(keys) > 0 {
			b.WriteString("?")
			for i, k := range keys {
				if i > 0 {
					b.WriteString("&")
				}
				b.WriteString(k)
				b.WriteString("=")
				b.WriteString(escapeQualifier(qualifiers[k]))
			}
		}
	}
	return b.String()
}

// escapeSegment percent-encodes a single path segment (name), keeping only
// characters that never need encoding in a purl segment.
func escapeSegment(s string) string { return pctEncode(s, "/@?#% ") }

// escapeNamespace encodes a namespace but preserves '/' as a segment separator.
func escapeNamespace(s string) string { return pctEncode(s, "@?#% ") }

// escapeVersion encodes a version, leaving version-common punctuation intact so
// output matches conventional SBOMs (e.g. "5.1-2+deb11u1", "1.2.3~rc1").
func escapeVersion(s string) string { return pctEncode(s, "?#% ") }

// escapeQualifier encodes a qualifier value.
func escapeQualifier(s string) string { return pctEncode(s, "&=?#% ") }

const upperHex = "0123456789ABCDEF"

// pctEncode percent-encodes control characters and any byte in mustEncode.
func pctEncode(s, mustEncode string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f || strings.IndexByte(mustEncode, c) >= 0 {
			b.WriteByte('%')
			b.WriteByte(upperHex[c>>4])
			b.WriteByte(upperHex[c&0xf])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// distroQualifier renders a distro qualifier value like "alpine-3.19" or
// "debian-11" from an os-release ID and VERSION_ID.
func distroQualifier(id, versionID string) string {
	id = strings.TrimSpace(id)
	versionID = strings.TrimSpace(versionID)
	switch {
	case id == "":
		return ""
	case versionID == "":
		return id
	default:
		return id + "-" + versionID
	}
}

// cpe23 builds a minimal CPE 2.3 formatted string for an OS/library component.
// Only vendor, product, and version are populated; other attributes are ANY.
func cpe23(vendor, product, version string) string {
	f := func(s string) string {
		if s == "" {
			return "*"
		}
		return cpeEscape(strings.ToLower(s))
	}
	return "cpe:2.3:a:" + f(vendor) + ":" + f(product) + ":" + f(version) + ":*:*:*:*:*:*:*"
}

// cpeEscape escapes CPE 2.3 special characters in a component attribute.
func cpeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case ':', '/', '?', '*', '\\', '(', ')', '[', ']', '{', '}', '!', '"', '#', '$', '%', '&', '\'', '+', ',', '.', ';', '<', '=', '>', '@', '^', '`', '|', '~':
			b.WriteByte('\\')
			b.WriteRune(r)
		case ' ':
			b.WriteByte('_')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
