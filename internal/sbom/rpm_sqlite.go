package sbom

import (
	"encoding/binary"
	"fmt"
)

// rpmSQLiteBackend reads RPM header blobs from a `rpmdb.sqlite` database — the
// default backend on RHEL 9+/Fedora. It is a minimal, read-only SQLite reader:
// it parses the file header, walks the sqlite_master table to find the
// `Packages` table's root page, then walks that table b-tree (following
// overflow-page chains for large records) and returns each row's BLOB column,
// which is a raw RPM header the shared rpm_header parser then decodes. It
// depends on nothing beyond the standard library.
type rpmSQLiteBackend struct{}

func (rpmSQLiteBackend) name() string { return "sqlite" }

func (b rpmSQLiteBackend) headers(data []byte) ([][]byte, error) {
	db, err := openSQLite(data)
	if err != nil {
		return nil, err
	}
	root, err := db.tableRoot("Packages")
	if err != nil {
		return nil, err
	}
	var blobs [][]byte
	err = db.walkTable(root, map[int]bool{}, func(payload []byte) {
		if blob := firstBlobColumn(payload); blob != nil {
			blobs = append(blobs, blob)
		}
	})
	if err != nil {
		return nil, err
	}
	return blobs, nil
}

// --- SQLite file plumbing --------------------------------------------------

type sqliteDB struct {
	data     []byte
	pageSize int
	usable   int // page size minus reserved trailing bytes
}

func openSQLite(data []byte) (*sqliteDB, error) {
	if len(data) < 100 || string(data[:16]) != "SQLite format 3\x00" {
		return nil, fmt.Errorf("not a SQLite 3 database")
	}
	ps := int(binary.BigEndian.Uint16(data[16:18]))
	if ps == 1 {
		ps = 65536 // the documented escape for a 64 KiB page size
	}
	if ps < 512 || ps&(ps-1) != 0 {
		return nil, fmt.Errorf("implausible SQLite page size %d", ps)
	}
	reserved := int(data[20])
	return &sqliteDB{data: data, pageSize: ps, usable: ps - reserved}, nil
}

// page returns the bytes of 1-indexed page p.
func (db *sqliteDB) page(p int) ([]byte, error) {
	if p < 1 {
		return nil, fmt.Errorf("invalid page number %d", p)
	}
	start := (p - 1) * db.pageSize
	if start+db.pageSize > len(db.data) {
		return nil, fmt.Errorf("page %d out of range", p)
	}
	return db.data[start : start+db.pageSize], nil
}

// tableRoot finds a table's root page by scanning sqlite_master (rooted at
// page 1): rows are (type, name, tbl_name, rootpage, sql); we match name.
func (db *sqliteDB) tableRoot(name string) (int, error) {
	root := 0
	err := db.walkTable(1, map[int]bool{}, func(payload []byte) {
		cols := decodeRecord(payload)
		if len(cols) >= 4 && cols[1].text() == name {
			root = int(cols[3].int())
		}
	})
	if err != nil {
		return 0, err
	}
	if root == 0 {
		return 0, fmt.Errorf("table %q not found in sqlite_master", name)
	}
	return root, nil
}

// walkTable recurses a table b-tree from page p, invoking visit with each leaf
// cell's full (overflow-reassembled) payload. seen guards against cycles.
func (db *sqliteDB) walkTable(p int, seen map[int]bool, visit func(payload []byte)) error {
	if seen[p] {
		return fmt.Errorf("cyclic b-tree page reference at %d", p)
	}
	seen[p] = true

	page, err := db.page(p)
	if err != nil {
		return err
	}
	hdr := 0
	if p == 1 {
		hdr = 100 // page 1 shares its first 100 bytes with the file header
	}
	if hdr >= len(page) {
		return fmt.Errorf("page %d truncated", p)
	}
	pageType := page[hdr]
	numCells := int(binary.BigEndian.Uint16(page[hdr+3 : hdr+5]))

	switch pageType {
	case 0x0D: // leaf table
		ptrs := hdr + 8
		for i := 0; i < numCells; i++ {
			off := ptrs + i*2
			if off+2 > len(page) {
				return fmt.Errorf("cell pointer %d out of range on page %d", i, p)
			}
			cell := int(binary.BigEndian.Uint16(page[off : off+2]))
			payload, err := db.readLeafCell(page, cell)
			if err != nil {
				return err
			}
			visit(payload)
		}
		return nil
	case 0x05: // interior table
		ptrs := hdr + 12
		for i := 0; i < numCells; i++ {
			off := ptrs + i*2
			if off+2 > len(page) {
				return fmt.Errorf("cell pointer %d out of range on page %d", i, p)
			}
			cell := int(binary.BigEndian.Uint16(page[off : off+2]))
			if cell+4 > len(page) {
				return fmt.Errorf("interior cell out of range on page %d", p)
			}
			child := int(binary.BigEndian.Uint32(page[cell : cell+4]))
			if err := db.walkTable(child, seen, visit); err != nil {
				return err
			}
		}
		// The right-most child pointer lives in the page header.
		right := int(binary.BigEndian.Uint32(page[hdr+8 : hdr+12]))
		return db.walkTable(right, seen, visit)
	default:
		return fmt.Errorf("unexpected b-tree page type 0x%02x on page %d (not a table)", pageType, p)
	}
}

// readLeafCell reads a table-leaf cell at offset off and returns its full
// record payload, following the overflow chain when the payload does not fit.
func (db *sqliteDB) readLeafCell(page []byte, off int) ([]byte, error) {
	if off >= len(page) {
		return nil, fmt.Errorf("leaf cell offset out of range")
	}
	payloadLen, n := uvarint(page[off:])
	off += n
	_, n = uvarint(page[off:]) // rowid — unused (blob column carries the data)
	off += n

	U := db.usable
	X := U - 35 // max payload stored on a table-leaf page
	P := int(payloadLen)
	if P < 0 || P > 1<<30 {
		return nil, fmt.Errorf("implausible payload length %d", P)
	}
	local := P
	if P > X {
		M := ((U - 12) * 32 / 255) - 23
		K := M + ((P - M) % (U - 4))
		if K <= X {
			local = K
		} else {
			local = M
		}
	}
	if off+local > len(page) {
		return nil, fmt.Errorf("cell local payload exceeds page")
	}
	out := make([]byte, 0, P)
	out = append(out, page[off:off+local]...)

	if local < P {
		// The 4 bytes after the local payload point at the first overflow page.
		if off+local+4 > len(page) {
			return nil, fmt.Errorf("missing overflow pointer")
		}
		next := int(binary.BigEndian.Uint32(page[off+local : off+local+4]))
		guard := 0
		for next != 0 && len(out) < P {
			if guard++; guard > 1<<20 {
				return nil, fmt.Errorf("overflow chain too long")
			}
			opage, err := db.page(next)
			if err != nil {
				return nil, err
			}
			next = int(binary.BigEndian.Uint32(opage[0:4]))
			chunk := opage[4:U]
			if take := P - len(out); take < len(chunk) {
				chunk = chunk[:take]
			}
			out = append(out, chunk...)
		}
	}
	if len(out) != P {
		return nil, fmt.Errorf("reassembled payload %d != declared %d", len(out), P)
	}
	return out, nil
}

// --- record decoding -------------------------------------------------------

type sqliteCol struct {
	serial uint64
	bytes  []byte
}

func (c sqliteCol) text() string { return string(c.bytes) }

// int decodes a big-endian twos-complement integer column (serial types 1-6).
func (c sqliteCol) int() int64 {
	var v int64
	for _, b := range c.bytes {
		v = v<<8 | int64(b)
	}
	// sign-extend
	if bits := len(c.bytes) * 8; bits > 0 && bits < 64 && c.bytes[0]&0x80 != 0 {
		v -= 1 << uint(bits)
	}
	switch c.serial {
	case 8:
		return 0
	case 9:
		return 1
	}
	return v
}

// decodeRecord parses a SQLite record (header of serial types + body) into
// columns. Malformed input yields whatever could be parsed, never a panic.
func decodeRecord(rec []byte) []sqliteCol {
	if len(rec) == 0 {
		return nil
	}
	hdrLen, n := uvarint(rec)
	if n == 0 || int(hdrLen) > len(rec) {
		return nil
	}
	var serials []uint64
	for i := n; i < int(hdrLen); {
		s, m := uvarint(rec[i:])
		if m == 0 {
			break
		}
		serials = append(serials, s)
		i += m
	}
	body := int(hdrLen)
	cols := make([]sqliteCol, 0, len(serials))
	for _, s := range serials {
		sz := serialSize(s)
		if body+sz > len(rec) {
			break
		}
		cols = append(cols, sqliteCol{serial: s, bytes: rec[body : body+sz]})
		body += sz
	}
	return cols
}

// firstBlobColumn returns the first BLOB column's bytes from a record payload.
func firstBlobColumn(payload []byte) []byte {
	for _, c := range decodeRecord(payload) {
		if c.serial >= 12 && c.serial%2 == 0 {
			return c.bytes
		}
	}
	return nil
}

// serialSize returns the content byte length for a SQLite serial type.
func serialSize(s uint64) int {
	switch s {
	case 0, 8, 9:
		return 0
	case 1:
		return 1
	case 2:
		return 2
	case 3:
		return 3
	case 4:
		return 4
	case 5:
		return 6
	case 6, 7:
		return 8
	}
	if s >= 12 {
		return int((s - 12) / 2) // even → BLOB, odd → TEXT; both use this length
	}
	return 0
}

// uvarint decodes a SQLite big-endian variable-length integer (1-9 bytes),
// returning the value and the number of bytes consumed (0 on failure).
func uvarint(b []byte) (uint64, int) {
	var v uint64
	for i := 0; i < 8; i++ {
		if i >= len(b) {
			return 0, 0
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	if len(b) < 9 {
		return 0, 0
	}
	return v<<8 | uint64(b[8]), 9
}
