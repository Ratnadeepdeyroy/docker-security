package vulndb

import "testing"

func TestParsePURL(t *testing.T) {
	tests := []struct {
		purl    string
		wantEco Ecosystem
		wantPkg string
		wantVer string
		wantSch VersionScheme
	}{
		{"pkg:apk/alpine/busybox@1.36.1-r5?arch=x86_64&distro=alpine-3.19", "alpine", "busybox", "1.36.1-r5", SchemeAPK},
		{"pkg:deb/debian/openssl@1.1.1n-0%2Bdeb11u5?arch=amd64", "debian", "openssl", "1.1.1n-0+deb11u5", SchemeDeb},
		{"pkg:rpm/rhel/glibc@2.34-60.el9?arch=x86_64&epoch=0", "rhel", "glibc", "2.34-60.el9", SchemeRPM},
		{"pkg:npm/lodash@4.17.20", "npm", "lodash", "4.17.20", SchemeSemver},
		{"pkg:npm/%40angular/core@12.0.0", "npm", "@angular/core", "12.0.0", SchemeSemver}, // scoped
		{"pkg:pypi/Django@3.2.1", "pypi", "django", "3.2.1", SchemePEP440},                 // PEP 503 normalized
		{"pkg:golang/github.com/gin-gonic/gin@v1.7.0", "go", "github.com/gin-gonic/gin", "v1.7.0", SchemeGo},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "maven", "org.apache.logging.log4j:log4j-core", "2.14.1", SchemeMaven},
		{"pkg:cargo/serde@1.0.130", "cargo", "serde", "1.0.130", SchemeSemver},
		{"pkg:gem/rails@6.1.0", "rubygems", "rails", "6.1.0", SchemeGem},
		{"pkg:composer/monolog/monolog@2.0.0", "composer", "monolog/monolog", "2.0.0", SchemeSemver},
	}
	for _, tc := range tests {
		t.Run(tc.purl, func(t *testing.T) {
			c, ok := ParsePURL(tc.purl)
			if !ok {
				t.Fatalf("ParsePURL(%q) failed", tc.purl)
			}
			if c.Ecosystem != tc.wantEco {
				t.Errorf("ecosystem = %q, want %q", c.Ecosystem, tc.wantEco)
			}
			if c.Package != tc.wantPkg {
				t.Errorf("package = %q, want %q", c.Package, tc.wantPkg)
			}
			if c.Version != tc.wantVer {
				t.Errorf("version = %q, want %q", c.Version, tc.wantVer)
			}
			if c.Scheme != tc.wantSch {
				t.Errorf("scheme = %q, want %q", c.Scheme, tc.wantSch)
			}
		})
	}
}

func TestParsePURLRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"", "not-a-purl", "pkg:", "pkg:npm", "http://example.com"} {
		if _, ok := ParsePURL(bad); ok {
			t.Errorf("ParsePURL(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestFromCatalogerFallback(t *testing.T) {
	c, ok := FromCataloger("apk-db", "musl", "1.2.4-r2", "alpine")
	if !ok || c.Ecosystem != "alpine" || c.Scheme != SchemeAPK || c.Package != "musl" {
		t.Errorf("FromCataloger apk = %+v, ok=%v", c, ok)
	}
	if _, ok := FromCataloger("unknown-cataloger", "x", "1", ""); ok {
		t.Errorf("FromCataloger should reject unknown cataloger")
	}
}
