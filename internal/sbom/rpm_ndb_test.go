package sbom

import (
	"encoding/binary"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// buildNDB synthesizes a minimal but format-valid ndb `Packages.db` holding the
// given RPM header blobs, matching the layout rpmNDBBackend reads.
func buildNDB(blobs [][]byte) []byte {
	le := binary.LittleEndian
	nslots := len(blobs) + 1 // slot 0 is the header slot

	// Region 1: header (32) + slot table.
	slotTableEnd := ndbHeaderSize + len(blobs)*ndbSlotSize
	// Blobs start on the next 16-byte-aligned block boundary.
	blobArea := (slotTableEnd + ndbBlobAlign - 1) / ndbBlobAlign * ndbBlobAlign

	// First pass: lay out blob offsets (block-aligned).
	type placed struct {
		blkOff uint32
		data   []byte
	}
	var ps []placed
	cursor := blobArea
	for _, b := range blobs {
		blkOff := uint32(cursor / ndbBlobAlign)
		total := ndbBlobHdrSize + len(b)
		ps = append(ps, placed{blkOff: blkOff, data: b})
		cursor += (total + ndbBlobAlign - 1) / ndbBlobAlign * ndbBlobAlign
	}

	out := make([]byte, cursor)
	// Header.
	le.PutUint32(out[0:4], ndbHeaderMagic)
	le.PutUint32(out[4:8], 0)                // version
	le.PutUint32(out[8:12], 1)               // generation
	le.PutUint32(out[12:16], uint32(nslots)) // slot count incl header slot

	// Slot entries.
	for i, p := range ps {
		off := ndbHeaderSize + i*ndbSlotSize
		le.PutUint32(out[off:off+4], ndbSlotMagic)
		le.PutUint32(out[off+4:off+8], uint32(i+1)) // pkgIdx (1-based, nonzero)
		le.PutUint32(out[off+8:off+12], p.blkOff)
		le.PutUint32(out[off+12:off+16], 1) // blkCount (unused by reader)
	}

	// Blob regions.
	for i, p := range ps {
		start := int(p.blkOff) * ndbBlobAlign
		le.PutUint32(out[start:start+4], ndbBlobMagicBlb)
		le.PutUint32(out[start+4:start+8], uint32(i+1)) // pkgIdx
		le.PutUint32(out[start+8:start+12], uint32(len(p.data)))
		copy(out[start+ndbBlobHdrSize:], p.data)
	}
	return out
}

func TestNDBBackendDecodesHeaders(t *testing.T) {
	blob := buildRPMHeader([]rpmField{
		rpmString(rpmTagName, "libzypp"),
		rpmString(rpmTagVersion, "17.31.0"),
		rpmString(rpmTagRelease, "1.1"),
		rpmString(rpmTagArch, "x86_64"),
		rpmString(rpmTagLicense, "GPL-2.0-or-later"),
	}, true)
	db := buildNDB([][]byte{blob})

	got, err := (rpmNDBBackend{}).headers(db)
	if err != nil {
		t.Fatalf("ndb headers: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 header, got %d", len(got))
	}
	pkg, err := parseRPMHeader(got[0])
	if err != nil {
		t.Fatalf("parse decoded header: %v", err)
	}
	if pkg.Name != "libzypp" || pkg.evr() != "17.31.0-1.1" {
		t.Errorf("decoded pkg = %q %q", pkg.Name, pkg.evr())
	}
}

func TestNDBBackendMultiPackage(t *testing.T) {
	mk := func(name, ver string) []byte {
		return buildRPMHeader([]rpmField{rpmString(rpmTagName, name), rpmString(rpmTagVersion, ver)}, true)
	}
	db := buildNDB([][]byte{mk("aaa", "1.0"), mk("bbb", "2.0"), mk("ccc", "3.0")})
	got, err := (rpmNDBBackend{}).headers(db)
	if err != nil {
		t.Fatalf("ndb headers: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 headers, got %d", len(got))
	}
}

func TestNDBDetectedAndCatalogued(t *testing.T) {
	blob := buildRPMHeader([]rpmField{
		rpmString(rpmTagName, "openssl"), rpmString(rpmTagVersion, "3.1.4"),
		rpmString(rpmTagRelease, "1.1"), rpmString(rpmTagArch, "x86_64"),
	}, true)
	tree := oci.TreeFromMap(map[string][]byte{
		"etc/os-release":          []byte("ID=opensuse-leap\nVERSION_ID=15.5\n"),
		"var/lib/rpm/Packages.db": buildNDB([][]byte{blob}),
	})
	comps, _, err := (rpmCataloger{}).Catalog(tree, detectDistro(tree))
	if err != nil {
		t.Fatalf("Catalog ndb: %v", err)
	}
	if len(comps) != 1 || comps[0].Name != "openssl" {
		t.Fatalf("ndb cataloging failed: %+v", comps)
	}
}
