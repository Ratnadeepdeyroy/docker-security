package sbom

import (
	"encoding/binary"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// buildBDB synthesizes a minimal Berkeley DB hash `Packages` file that the
// rpmBDBBackend can read: a metadata page (page 0), one hash page (page 1) with a
// single H_OFFPAGE entry per blob, and one overflow page per blob carrying the
// RPM header. Little-endian, page size 4096.
func buildBDB(blobs [][]byte) []byte {
	le := binary.LittleEndian
	const pageSize = 4096
	numPages := 2 + len(blobs) // meta + hash + one overflow page per blob (each blob fits one page here)
	out := make([]byte, pageSize*numPages)

	// --- Metadata page (page 0) ---
	le.PutUint32(out[12:16], bdbHashMagic)       // magic at offset 12
	le.PutUint32(out[20:24], pageSize)           // page size at offset 20
	le.PutUint32(out[32:36], uint32(numPages-1)) // last-page number at offset 32
	out[25] = 9                                  // meta page type (P_HASHMETA); reader ignores page 0 type

	// --- Hash page (page 1) ---
	hp := 1 * pageSize
	page := out[hp : hp+pageSize]
	page[25] = bdbHashPage
	le.PutUint16(page[20:22], uint16(len(blobs))) // entry count at offset 20

	// Entry index array starts at bdbPageHdrSize; each entry is an H_OFFPAGE
	// record placed toward the end of the page.
	entryOff := pageSize - len(blobs)*12
	for i := range blobs {
		// index slot i -> offset of this entry
		le.PutUint16(page[bdbPageHdrSize+i*2:bdbPageHdrSize+i*2+2], uint16(entryOff+i*12))
	}

	// --- Overflow pages (one blob each) ---
	for i, b := range blobs {
		ovPageNo := uint32(2 + i)
		// H_OFFPAGE entry: [type u8][unused 3][pgno u32][tlen u32]
		e := entryOff + i*12
		page[e] = bdbHOffPage
		le.PutUint32(page[e+4:e+8], ovPageNo)
		le.PutUint32(page[e+8:e+12], uint32(len(b)))

		ov := out[int(ovPageNo)*pageSize : int(ovPageNo)*pageSize+pageSize]
		ov[25] = bdbOverflow
		le.PutUint32(ov[16:20], 0)              // next page = 0 (single-page value)
		le.PutUint16(ov[22:24], uint16(len(b))) // hf: bytes used on this page
		copy(ov[bdbPageHdrSize:], b)
	}
	return out
}

func TestBDBBackendDecodesHeaders(t *testing.T) {
	blob := buildRPMHeader([]rpmField{
		rpmString(rpmTagName, "glibc"),
		rpmString(rpmTagVersion, "2.28"),
		rpmString(rpmTagRelease, "164.el8"),
		rpmString(rpmTagArch, "x86_64"),
		rpmString(rpmTagLicense, "LGPL-2.1-or-later"),
	}, true)
	db := buildBDB([][]byte{blob})

	got, err := (rpmBDBBackend{}).headers(db)
	if err != nil {
		t.Fatalf("bdb headers: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 header, got %d", len(got))
	}
	pkg, err := parseRPMHeader(got[0])
	if err != nil {
		t.Fatalf("parse decoded header: %v", err)
	}
	if pkg.Name != "glibc" || pkg.evr() != "2.28-164.el8" {
		t.Errorf("decoded pkg = %q %q", pkg.Name, pkg.evr())
	}
}

func TestBDBBackendMultiPackage(t *testing.T) {
	mk := func(name, ver string) []byte {
		return buildRPMHeader([]rpmField{rpmString(rpmTagName, name), rpmString(rpmTagVersion, ver)}, true)
	}
	db := buildBDB([][]byte{mk("bash", "4.4"), mk("coreutils", "8.30")})
	got, err := (rpmBDBBackend{}).headers(db)
	if err != nil {
		t.Fatalf("bdb headers: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 headers, got %d", len(got))
	}
}

func TestBDBDetectedAndCatalogued(t *testing.T) {
	blob := buildRPMHeader([]rpmField{
		rpmString(rpmTagName, "curl"), rpmString(rpmTagVersion, "7.61.1"),
		rpmString(rpmTagRelease, "22.el8"), rpmString(rpmTagArch, "x86_64"),
	}, true)
	tree := oci.TreeFromMap(map[string][]byte{
		"etc/os-release":       []byte("ID=rhel\nVERSION_ID=8\n"),
		"var/lib/rpm/Packages": buildBDB([][]byte{blob}),
	})
	comps, _, err := (rpmCataloger{}).Catalog(tree, detectDistro(tree))
	if err != nil {
		t.Fatalf("Catalog bdb: %v", err)
	}
	if len(comps) != 1 || comps[0].Name != "curl" {
		t.Fatalf("bdb cataloging failed: %+v", comps)
	}
}

func TestBDBBigEndianMagic(t *testing.T) {
	// A big-endian metadata magic must also be recognized by isBDBHash.
	data := make([]byte, 512)
	binary.BigEndian.PutUint32(data[12:16], bdbHashMagic)
	if !isBDBHash(data) {
		t.Error("big-endian bdb magic not detected")
	}
}
