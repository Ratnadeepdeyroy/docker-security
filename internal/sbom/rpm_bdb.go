package sbom

import (
	"encoding/binary"
	"fmt"
)

// rpmBDBBackend reads RPM header blobs from a Berkeley DB "hash" database
// (`Packages`), the backend used by RHEL/CentOS ≤ 8. rpm stores each installed
// package's raw header as a value in the hash DB; the keys are package install
// numbers we do not need. We implement the minimal read path used by other
// pure-language rpmdb readers: parse the BDB metadata page to learn the page
// size and last page, then walk every hash page's on-page entries, following
// H_OFFPAGE overflow chains to reassemble values that span pages. Each value is
// a raw RPM header the shared parser decodes.
//
// This targets the DB hash on-disk format (magic 0x00061561), byte-order
// autodetected from the metadata magic, which is what rpm writes. It reads only;
// it never interprets the DB's internal free lists beyond what walking pages
// needs.
type rpmBDBBackend struct{}

func (rpmBDBBackend) name() string { return "berkeley-db" }

const (
	bdbHashMagic   = 0x00061561
	bdbMetaSize    = 512 // generic metadata page prefix we read fields from
	bdbHashPage    = 8   // P_HASH page type
	bdbHashPage2   = 13  // P_HASH_UNSORTED (older) — treated the same for reads
	bdbOverflow    = 7   // P_OVERFLOW page type
	bdbHOffPage    = 3   // H_OFFPAGE entry type (value stored on overflow pages)
	bdbHKeyData    = 1   // H_KEYDATA entry type (inline value)
	bdbMaxPages    = 1 << 20
	bdbPageHdrSize = 26
)

type bdbReader struct {
	data     []byte
	pageSize int
	lastPage uint32
	be       binary.ByteOrder
}

func (rpmBDBBackend) headers(data []byte) ([][]byte, error) {
	r, err := openBDB(data)
	if err != nil {
		return nil, err
	}
	var blobs [][]byte
	// Values alternate key/data in hash pages; rpm's values are the RPM headers.
	// We collect every data entry and let the header parser reject non-headers.
	for pageNo := uint32(0); pageNo <= r.lastPage; pageNo++ {
		entries, err := r.pageDataEntries(pageNo)
		if err != nil {
			continue // skip an unreadable page rather than failing the DB
		}
		for _, e := range entries {
			if looksLikeRPMHeader(e) {
				blobs = append(blobs, e)
			}
		}
	}
	if len(blobs) == 0 {
		return nil, fmt.Errorf("berkeley-db: no package headers found")
	}
	return blobs, nil
}

func openBDB(data []byte) (*bdbReader, error) {
	if len(data) < bdbMetaSize {
		return nil, fmt.Errorf("berkeley-db: file shorter than metadata page")
	}
	// The magic sits at offset 12 in the metadata page. Try both byte orders.
	var be binary.ByteOrder
	switch {
	case binary.LittleEndian.Uint32(data[12:16]) == bdbHashMagic:
		be = binary.LittleEndian
	case binary.BigEndian.Uint32(data[12:16]) == bdbHashMagic:
		be = binary.BigEndian
	default:
		return nil, fmt.Errorf("berkeley-db: not a DB hash database (bad magic)")
	}
	pageSize := int(be.Uint32(data[20:24]))
	if pageSize < 512 || pageSize&(pageSize-1) != 0 || pageSize > 1<<20 {
		return nil, fmt.Errorf("berkeley-db: implausible page size %d", pageSize)
	}
	lastPage := be.Uint32(data[32:36])
	if lastPage > bdbMaxPages {
		return nil, fmt.Errorf("berkeley-db: implausible last-page %d", lastPage)
	}
	return &bdbReader{data: data, pageSize: pageSize, lastPage: lastPage, be: be}, nil
}

// pageDataEntries returns the value blobs stored on a hash page, resolving
// H_OFFPAGE overflow references. Non-hash pages return no entries.
func (r *bdbReader) pageDataEntries(pageNo uint32) ([][]byte, error) {
	start := int(pageNo) * r.pageSize
	if start+bdbPageHdrSize > len(r.data) {
		return nil, fmt.Errorf("page %d out of range", pageNo)
	}
	page := r.data[start : start+r.pageSize]
	pageType := page[25]
	if pageType != bdbHashPage && pageType != bdbHashPage2 {
		return nil, nil
	}
	numEntries := int(r.be.Uint16(page[20:22]))
	if numEntries <= 0 || numEntries > r.pageSize/2 {
		return nil, nil
	}

	var out [][]byte
	// Hash pages store entries as alternating key,data pairs; the index array of
	// 2-byte offsets to each entry begins right after the 26-byte page header.
	idx := bdbPageHdrSize
	for i := 0; i < numEntries; i++ {
		if idx+2 > len(page) {
			break
		}
		eoff := int(r.be.Uint16(page[idx : idx+2]))
		idx += 2
		if eoff <= 0 || eoff >= len(page) {
			continue
		}
		// Only data entries (odd index) carry the header; but rpm's key entries
		// are tiny ints, and looksLikeRPMHeader filters, so we inspect all.
		blob, ok := r.readHashEntry(page, eoff)
		if ok {
			out = append(out, blob)
		}
	}
	return out, nil
}

// readHashEntry decodes one hash entry at page offset off. It handles inline
// H_KEYDATA values and H_OFFPAGE overflow references.
func (r *bdbReader) readHashEntry(page []byte, off int) ([]byte, bool) {
	if off >= len(page) {
		return nil, false
	}
	etype := page[off]
	switch etype {
	case bdbHKeyData:
		// [type u8][unused u8][data...] up to the next entry; length is implicit,
		// so we cannot slice safely from the type alone. rpm's inline values are
		// small keys we don't want — skip; headers come via H_OFFPAGE.
		return nil, false
	case bdbHOffPage:
		// H_OFFPAGE: [type u8][unused 3][pgno u32][tlen u32]
		if off+12 > len(page) {
			return nil, false
		}
		pgno := r.be.Uint32(page[off+4 : off+8])
		tlen := r.be.Uint32(page[off+8 : off+12])
		return r.readOverflow(pgno, int(tlen))
	default:
		return nil, false
	}
}

// readOverflow reassembles a value stored across a chain of P_OVERFLOW pages.
func (r *bdbReader) readOverflow(pgno uint32, tlen int) ([]byte, bool) {
	if tlen <= 0 || tlen > 1<<26 {
		return nil, false
	}
	out := make([]byte, 0, tlen)
	guard := 0
	for pgno != 0 && len(out) < tlen {
		if guard++; guard > bdbMaxPages {
			return nil, false
		}
		start := int(pgno) * r.pageSize
		if start+bdbPageHdrSize > len(r.data) {
			return nil, false
		}
		page := r.data[start : start+r.pageSize]
		if page[25] != bdbOverflow {
			return nil, false
		}
		next := r.be.Uint32(page[16:20]) // next page number
		hf := int(r.be.Uint16(page[22:24]))
		// On an overflow page the payload occupies [hdr, hdr+hf) for the last page,
		// or the full usable span for a full page.
		avail := page[bdbPageHdrSize:]
		if next == 0 && hf > 0 && hf <= len(avail) {
			avail = avail[:hf]
		}
		take := tlen - len(out)
		if take < len(avail) {
			avail = avail[:take]
		}
		out = append(out, avail...)
		pgno = next
	}
	if len(out) != tlen {
		return nil, false
	}
	return out, true
}

// looksLikeRPMHeader is a cheap structural check so we only feed plausible blobs
// to the parser: it must start with the header magic or a sane il/dl prefix.
func looksLikeRPMHeader(b []byte) bool {
	if len(b) >= 8 && b[0] == 0x8e && b[1] == 0xad && b[2] == 0xe8 {
		return true
	}
	if len(b) < 8 {
		return false
	}
	il := binary.BigEndian.Uint32(b[0:4])
	dl := binary.BigEndian.Uint32(b[4:8])
	return il > 0 && il < 1<<16 && dl > 0 && dl < 1<<24 && len(b) >= 8+int(il)*16
}
