package vulndb

import "strings"

// --- PURL → advisory coordinate -----------------------------------------

// Coord is the normalized lookup key derived from an SBOM component: the feed
// ecosystem an advisory would live under, the package name as that feed spells
// it, the installed version, and the scheme to compare versions with.
type Coord struct {
	Ecosystem Ecosystem
	Package   string
	Version   string
	Scheme    VersionScheme
}

// ParsePURL turns a Package URL into a Coord. It reconstructs ecosystem-correct
// package names (scoped npm "@scope/name", Go module paths, Maven
// "group:artifact") so the name matches how advisory feeds key that ecosystem —
// the difference between a hit and a silent miss. ok is false for a PURL we
// cannot classify.
func ParsePURL(purl string) (Coord, bool) {
	if !strings.HasPrefix(purl, "pkg:") {
		return Coord{}, false
	}
	body := strings.TrimPrefix(purl, "pkg:")
	body = cutAt(body, '#') // drop subpath

	coordPart, qualPart := body, ""
	if i := strings.IndexByte(body, '?'); i >= 0 {
		coordPart, qualPart = body[:i], body[i+1:]
	}
	quals := parseQualifiers(qualPart)

	typ, rest, ok := strings.Cut(coordPart, "/")
	if !ok {
		return Coord{}, false
	}
	typ = strings.ToLower(typ)

	version := ""
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		version = pctDecode(rest[i+1:])
		rest = rest[:i]
	}
	namespace, name := "", rest
	if i := strings.LastIndexByte(rest, '/'); i >= 0 {
		namespace, name = rest[:i], rest[i+1:]
	}
	namespace = pctDecode(namespace)
	name = pctDecode(name)

	c := Coord{Version: version}
	switch typ {
	case "apk":
		c.Ecosystem = osEcosystem(namespace, quals, "alpine")
		c.Package, c.Scheme = name, SchemeAPK
	case "deb":
		c.Ecosystem = osEcosystem(namespace, quals, "debian")
		c.Package, c.Scheme = name, SchemeDeb
	case "rpm":
		c.Ecosystem = osEcosystem(namespace, quals, "redhat")
		c.Package, c.Scheme = name, SchemeRPM
	case "npm":
		c.Ecosystem, c.Scheme = "npm", SchemeSemver
		c.Package = joinScoped(namespace, name)
	case "pypi":
		c.Ecosystem, c.Scheme = "pypi", SchemePEP440
		c.Package = NormalizePyPI(name)
	case "golang":
		c.Ecosystem, c.Scheme = "go", SchemeGo
		c.Package = joinPath(namespace, name, "/")
	case "maven":
		c.Ecosystem, c.Scheme = "maven", SchemeMaven
		c.Package = joinPath(namespace, name, ":")
	case "cargo":
		c.Ecosystem, c.Scheme = "cargo", SchemeSemver
		c.Package = name
	case "gem":
		c.Ecosystem, c.Scheme = "rubygems", SchemeGem
		c.Package = name
	case "composer":
		c.Ecosystem, c.Scheme = "composer", SchemeSemver
		c.Package = joinPath(namespace, name, "/")
	case "nuget":
		c.Ecosystem, c.Scheme = "nuget", SchemeSemver
		c.Package = name
	default:
		c.Ecosystem = Ecosystem(typ)
		c.Package, c.Scheme = name, SchemeGeneric
	}
	if c.Package == "" {
		return Coord{}, false
	}
	return c, true
}

// FromCataloger builds a Coord from an SBOM component that lacks a usable PURL,
// using the cataloger (found_by) name to pick an ecosystem. This keeps coverage
// for components a cataloger recorded without a PURL rather than dropping them.
func FromCataloger(foundBy, name, version, distroID string) (Coord, bool) {
	if name == "" {
		return Coord{}, false
	}
	c := Coord{Package: name, Version: version}
	switch foundBy {
	case "apk-db":
		c.Ecosystem, c.Scheme = orDefault(distroID, "alpine"), SchemeAPK
	case "dpkg-db":
		c.Ecosystem, c.Scheme = orDefault(distroID, "debian"), SchemeDeb
	case "rpm-db":
		c.Ecosystem, c.Scheme = orDefault(distroID, "redhat"), SchemeRPM
	case "npm":
		c.Ecosystem, c.Scheme = "npm", SchemeSemver
	case "python":
		c.Ecosystem, c.Scheme = "pypi", SchemePEP440
		c.Package = NormalizePyPI(name)
	case "go-module":
		c.Ecosystem, c.Scheme = "go", SchemeGo
	default:
		return Coord{}, false
	}
	return c, true
}

func osEcosystem(namespace string, quals map[string]string, fallback string) Ecosystem {
	if namespace != "" {
		return Ecosystem(strings.ToLower(namespace))
	}
	if d := quals["distro"]; d != "" {
		return Ecosystem(strings.ToLower(cutAt(d, '-')))
	}
	return Ecosystem(fallback)
}

func orDefault(v, def string) Ecosystem {
	if v == "" {
		return Ecosystem(def)
	}
	return Ecosystem(strings.ToLower(v))
}

// joinScoped reconstructs a scoped npm name; namespace already carries the '@'.
func joinScoped(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "/" + name
}

func joinPath(namespace, name, sep string) string {
	if namespace == "" {
		return name
	}
	return namespace + sep + name
}

func parseQualifiers(s string) map[string]string {
	out := map[string]string{}
	if s == "" {
		return out
	}
	for _, kv := range strings.Split(s, "&") {
		k, v, ok := strings.Cut(kv, "=")
		if ok {
			out[strings.ToLower(k)] = pctDecode(v)
		}
	}
	return out
}

// NormalizePyPI applies PEP 503 name normalization (lowercase, collapse runs of
// "-", "_", "." to a single "-"), matching how PyPI advisory feeds key names.
func NormalizePyPI(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	prevSep := false
	for _, r := range name {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('-')
				prevSep = true
			}
			continue
		}
		b.WriteRune(r)
		prevSep = false
	}
	return strings.Trim(b.String(), "-")
}

// pctDecode reverses percent-encoding. Malformed escapes are left as-is rather
// than erroring, so a hostile PURL cannot break parsing.
func pctDecode(s string) string {
	if !strings.ContainsRune(s, '%') {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := hexVal(s[i+1])
			lo, ok2 := hexVal(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}
