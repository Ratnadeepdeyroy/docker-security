package sbom

import (
	"encoding/binary"
	"fmt"
)

// rpmNDBBackend reads RPM header blobs from an "ndb" database (`Packages.db`),
// the backend used by openSUSE/SLES and available on modern rpm. The format is a
// small, well-defined slot store: a fixed header, then a run of fixed-size slot
// entries, each pointing at a block-aligned region that holds one package's raw
// RPM header. We follow the on-disk layout from rpm's lib/backend/ndb and return
// each package's header blob for the shared rpm_header parser.
//
// Layout (all little-endian):
//
//	Header (NDB_HeaderSize = 4*8 = 32 bytes):
//	  magic 'RpmP' (0x50006d52 as u32 LE of "RpmP"), version, generation,
//	  nbdbslots (slot count incl. header slot), ...
//	Slot entries (NDB_SlotEntrySize = 16 bytes each), starting at offset 32:
//	  slotMagic 'Slot', pkgIdx (u32), blkOffset (u32), blkCount (u32)
//	A slot with pkgIdx==0 is free/header. Package data begins at
//	blkOffset * NDB_BlobAlign, prefixed by a blob header (NDB_BlobHeaderSize):
//	  blobMagic 'BlbS', pkgIdx, blobLen(u32), then the RPM header blob.
type rpmNDBBackend struct{}

func (rpmNDBBackend) name() string { return "ndb" }

const (
	ndbHeaderSize   = 32
	ndbSlotSize     = 16
	ndbBlobAlign    = 16
	ndbBlobHdrSize  = 16
	ndbSlotMagic    = 0x746f6c53 // "Slot" little-endian
	ndbHeaderMagic  = 0x506d7052 // "RpmP" little-endian
	ndbBlobMagicBlb = 0x53626c42 // "BlbS" little-endian
	ndbMaxPackages  = 1 << 20
)

func (rpmNDBBackend) headers(data []byte) ([][]byte, error) {
	if len(data) < ndbHeaderSize {
		return nil, fmt.Errorf("ndb: file shorter than header")
	}
	if binary.LittleEndian.Uint32(data[0:4]) != ndbHeaderMagic {
		return nil, fmt.Errorf("ndb: bad header magic")
	}
	nslots := int(binary.LittleEndian.Uint32(data[12:16]))
	if nslots < 1 || nslots > ndbMaxPackages {
		return nil, fmt.Errorf("ndb: implausible slot count %d", nslots)
	}

	var blobs [][]byte
	// Slot 0 is the header slot; real entries follow.
	for i := 1; i < nslots; i++ {
		off := ndbHeaderSize + (i-1)*ndbSlotSize
		if off+ndbSlotSize > len(data) {
			break
		}
		slot := data[off : off+ndbSlotSize]
		if binary.LittleEndian.Uint32(slot[0:4]) != ndbSlotMagic {
			continue // free/unused slot
		}
		pkgIdx := binary.LittleEndian.Uint32(slot[4:8])
		blkOff := binary.LittleEndian.Uint32(slot[8:12])
		if pkgIdx == 0 || blkOff == 0 {
			continue
		}
		blob, err := ndbReadBlob(data, blkOff)
		if err != nil {
			// A single corrupt slot must not sink the whole database.
			continue
		}
		blobs = append(blobs, blob)
	}
	if len(blobs) == 0 {
		return nil, fmt.Errorf("ndb: no package headers found")
	}
	return blobs, nil
}

// ndbReadBlob reads one package's RPM header blob at blkOffset*align.
func ndbReadBlob(data []byte, blkOff uint32) ([]byte, error) {
	start := int(blkOff) * ndbBlobAlign
	if start < 0 || start+ndbBlobHdrSize > len(data) {
		return nil, fmt.Errorf("ndb: blob offset out of range")
	}
	hdr := data[start : start+ndbBlobHdrSize]
	if binary.LittleEndian.Uint32(hdr[0:4]) != ndbBlobMagicBlb {
		return nil, fmt.Errorf("ndb: bad blob magic")
	}
	blobLen := int(binary.LittleEndian.Uint32(hdr[8:12]))
	if blobLen <= 0 || blobLen > 1<<26 {
		return nil, fmt.Errorf("ndb: implausible blob length %d", blobLen)
	}
	dataStart := start + ndbBlobHdrSize
	if dataStart+blobLen > len(data) {
		return nil, fmt.Errorf("ndb: blob exceeds file")
	}
	return data[dataStart : dataStart+blobLen], nil
}
