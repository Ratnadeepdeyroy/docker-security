package sbom

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// rpmdbFixture loads the committed rpmdb.sqlite (generated once via the sqlite3
// CLI from real RPM header blobs; see scripts/ / testdata). Row 1 fits inline;
// row 2 is oversized to force a SQLite overflow-page chain.
func rpmdbFixture(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "rpmdb.sqlite"))
	if err != nil {
		t.Skipf("rpmdb.sqlite fixture missing: %v", err)
	}
	return data
}

func TestRPMSQLiteBackendReadsHeaders(t *testing.T) {
	blobs, err := (rpmSQLiteBackend{}).headers(rpmdbFixture(t))
	if err != nil {
		t.Fatalf("sqlite headers: %v", err)
	}
	if len(blobs) != 2 {
		t.Fatalf("expected 2 header blobs, got %d", len(blobs))
	}
	byName := map[string]rpmPackage{}
	for _, b := range blobs {
		pkg, err := parseRPMHeader(b)
		if err != nil {
			t.Fatalf("parse header: %v", err)
		}
		byName[pkg.Name] = pkg
	}
	// Inline row.
	if got := byName["openssl"].evr(); got != "1:3.0.7-18.el9" {
		t.Errorf("openssl evr = %q, want 1:3.0.7-18.el9", got)
	}
	if byName["openssl"].Arch != "x86_64" {
		t.Errorf("openssl arch = %q", byName["openssl"].Arch)
	}
	// Overflow row: parsing it at all proves the overflow-chain reassembly.
	if _, ok := byName["bigpkg"]; !ok {
		t.Errorf("bigpkg (overflow row) not read back; names=%v", byName)
	}
}

func TestRPMCatalogerEndToEndSQLite(t *testing.T) {
	tree := oci.TreeFromMap(map[string][]byte{
		"etc/os-release":           []byte("ID=rhel\nVERSION_ID=9\n"),
		"var/lib/rpm/rpmdb.sqlite": rpmdbFixture(t),
	})
	comps, _, err := (rpmCataloger{}).Catalog(tree, detectDistro(tree))
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	got := map[string]Component{}
	for _, c := range comps {
		got[c.Name] = c
	}
	openssl, ok := got["openssl"]
	if !ok {
		t.Fatalf("openssl not cataloged from rpmdb.sqlite; got %d comps", len(comps))
	}
	want := "pkg:rpm/rhel/openssl@1:3.0.7-18.el9?arch=x86_64&distro=rhel-9&epoch=1"
	if openssl.PURL != want {
		t.Errorf("openssl PURL = %q, want %q", openssl.PURL, want)
	}
	if openssl.Type != TypeOS {
		t.Errorf("openssl should be an OS component")
	}
}
