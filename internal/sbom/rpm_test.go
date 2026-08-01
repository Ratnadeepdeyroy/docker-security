package sbom

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

type rpmField struct {
	tag   int32
	typ   uint32
	data  []byte
	count uint32
}

func rpmString(tag int32, s string) rpmField {
	return rpmField{tag: tag, typ: rpmTypeString, data: append([]byte(s), 0), count: 1}
}

func rpmInt32(tag int32, v uint32) rpmField {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return rpmField{tag: tag, typ: rpmTypeInt32, data: b, count: 1}
}

// buildRPMHeader assembles an on-disk RPM header blob from fields.
func buildRPMHeader(fields []rpmField, withMagic bool) []byte {
	var index, data bytes.Buffer
	put := func(w *bytes.Buffer, v uint32) {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v)
		w.Write(b)
	}
	for _, f := range fields {
		put(&index, uint32(f.tag))
		put(&index, f.typ)
		put(&index, uint32(data.Len()))
		put(&index, f.count)
		data.Write(f.data)
	}
	var out bytes.Buffer
	if withMagic {
		out.Write(rpmHeaderMagic)
		out.Write([]byte{0, 0, 0, 0}) // reserved
	}
	put(&out, uint32(len(fields)))
	put(&out, uint32(data.Len()))
	out.Write(index.Bytes())
	out.Write(data.Bytes())
	return out.Bytes()
}

func TestParseRPMHeader(t *testing.T) {
	blob := buildRPMHeader([]rpmField{
		rpmString(rpmTagName, "openssl"),
		rpmString(rpmTagVersion, "3.0.7"),
		rpmString(rpmTagRelease, "18.el9"),
		rpmString(rpmTagArch, "x86_64"),
		rpmString(rpmTagLicense, "Apache-2.0"),
		rpmInt32(rpmTagEpoch, 1),
	}, false)
	pkg, err := parseRPMHeader(blob)
	if err != nil {
		t.Fatalf("parseRPMHeader: %v", err)
	}
	if pkg.Name != "openssl" {
		t.Errorf("Name = %q", pkg.Name)
	}
	if got := pkg.evr(); got != "1:3.0.7-18.el9" {
		t.Errorf("evr = %q, want 1:3.0.7-18.el9", got)
	}
	if pkg.Arch != "x86_64" || pkg.License != "Apache-2.0" {
		t.Errorf("arch/license = %q/%q", pkg.Arch, pkg.License)
	}
}

func TestParseRPMHeaderWithMagic(t *testing.T) {
	blob := buildRPMHeader([]rpmField{rpmString(rpmTagName, "zlib"), rpmString(rpmTagVersion, "1.2.13")}, true)
	pkg, err := parseRPMHeader(blob)
	if err != nil {
		t.Fatalf("parseRPMHeader (magic): %v", err)
	}
	if pkg.Name != "zlib" || pkg.evr() != "1.2.13" {
		t.Errorf("got %q %q", pkg.Name, pkg.evr())
	}
}

func TestParseRPMHeaderRejectsTruncated(t *testing.T) {
	if _, err := parseRPMHeader([]byte{0, 0, 0, 1}); err == nil {
		t.Errorf("expected error on truncated blob")
	}
}

// fakeRPMBackend yields prebuilt header blobs, standing in for a real database
// decoder so the cataloger's identity/PURL logic can be tested hermetically.
type fakeRPMBackend struct{ blobs [][]byte }

func (fakeRPMBackend) name() string                       { return "fake" }
func (f fakeRPMBackend) headers([]byte) ([][]byte, error) { return f.blobs, nil }

func TestRPMCatalogerWithInjectedBackend(t *testing.T) {
	blob := buildRPMHeader([]rpmField{
		rpmString(rpmTagName, "openssl"),
		rpmString(rpmTagVersion, "3.0.7"),
		rpmString(rpmTagRelease, "18.el9"),
		rpmString(rpmTagArch, "x86_64"),
		rpmInt32(rpmTagEpoch, 1),
	}, false)
	c := rpmCataloger{backend: fakeRPMBackend{blobs: [][]byte{blob}}}
	tree := oci.TreeFromMap(map[string][]byte{
		"etc/os-release":       []byte("ID=rhel\nVERSION_ID=9\n"),
		"var/lib/rpm/Packages": []byte("ignored-by-fake-backend"),
	})
	comps, _, err := c.Catalog(tree, detectDistro(tree))
	if err != nil {
		t.Fatalf("Catalog: %v", err)
	}
	if len(comps) != 1 {
		t.Fatalf("expected 1 component, got %d", len(comps))
	}
	want := "pkg:rpm/rhel/openssl@1:3.0.7-18.el9?arch=x86_64&distro=rhel-9&epoch=1"
	if comps[0].PURL != want {
		t.Errorf("PURL = %q, want %q", comps[0].PURL, want)
	}
}

func TestRPMBackendDetectionDegradesCleanly(t *testing.T) {
	// All three real backends (sqlite, ndb, Berkeley DB hash) are implemented; an
	// unrecognized database format must still record a descriptive error rather
	// than silently dropping packages.
	tree := oci.TreeFromMap(map[string][]byte{
		"var/lib/rpm/Packages": []byte("\x00\x00\x00\x00\x00\x00\x00\x00not-a-known-rpmdb-format"),
	})
	_, _, err := (rpmCataloger{}).Catalog(tree, Distro{ID: "rhel", VersionID: "9"})
	if err == nil {
		t.Fatalf("expected a descriptive error for an unrecognized rpm database format")
	}
}
