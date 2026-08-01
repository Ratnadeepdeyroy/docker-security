package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// --- Flat-file backend ---------------------------------------------------
//
// Scans are stored one JSON file per scan, named "<id>.json", under a single
// directory. On Open the directory is read once into the in-memory index; from
// then on reads are served from memory and writes go to both. Writes are atomic
// (temp file + rename) so a crash mid-write never leaves a half-written record
// that would poison the next load.

// maxRecordBytes bounds a single scan file we are willing to read back. A
// hostile or corrupt file larger than this is skipped, not loaded into memory —
// the store must not be a denial-of-service vector against its own server.
const maxRecordBytes = 32 << 20 // 32 MiB

// idPattern is the only shape a stored filename may have. IDs we generate are
// 16 hex chars; enforcing this on load means a crafted filename like
// "../../etc/passwd.json" can never be interpreted as a record id.
var idPattern = regexp.MustCompile(`^[a-f0-9]{16}$`)

type fileBackend struct {
	dir string
}

// Open returns a file-backed store rooted at dir, creating the directory if
// needed and loading any scans already present. Corrupt or oversized files are
// skipped with a returned error listing them, but valid records still load —
// one bad file never blocks the whole inventory.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("store: create dir %q: %w", dir, err)
	}
	b := &fileBackend{dir: dir}
	s := &Store{scans: map[string]*Scan{}, backend: b}

	loaded, err := b.load()
	for _, sc := range loaded {
		s.scans[sc.ID] = sc
	}
	return s, err
}

// Dir reports the backing directory, or "" for a memory store.
func (s *Store) Dir() string {
	if b, ok := s.backend.(*fileBackend); ok {
		return b.dir
	}
	return ""
}

func (b *fileBackend) save(sc *Scan) error {
	if !idPattern.MatchString(sc.ID) {
		return fmt.Errorf("refusing to persist scan with unsafe id %q", sc.ID)
	}
	data, err := json.MarshalIndent(toWire(sc), "", "  ")
	if err != nil {
		return fmt.Errorf("marshal scan: %w", err)
	}
	final := filepath.Join(b.dir, sc.ID+".json")
	tmp, err := os.CreateTemp(b.dir, sc.ID+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close temp: %w", err)
	}
	// rename is atomic on the same filesystem, so a reader never sees a partial file.
	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename %s: %w", final, err)
	}
	return nil
}

func (b *fileBackend) load() ([]*Scan, error) {
	entries, err := os.ReadDir(b.dir)
	if err != nil {
		return nil, fmt.Errorf("read store dir: %w", err)
	}
	var out []*Scan
	var skipped []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		id := e.Name()[:len(e.Name())-len(".json")]
		if !idPattern.MatchString(id) {
			skipped = append(skipped, e.Name()+" (unsafe name)")
			continue
		}
		sc, err := b.readOne(id)
		if err != nil {
			skipped = append(skipped, e.Name()+" ("+err.Error()+")")
			continue
		}
		out = append(out, sc)
	}
	if len(skipped) > 0 {
		return out, fmt.Errorf("store: skipped %d unreadable record(s): %v", len(skipped), skipped)
	}
	return out, nil
}

// readOne reads and decodes a single record, enforcing the size bound before
// decoding so a decompression/allocation bomb cannot exhaust memory.
func (b *fileBackend) readOne(id string) (*Scan, error) {
	path := filepath.Join(b.dir, id+".json")
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxRecordBytes {
		return nil, fmt.Errorf("record %d bytes exceeds limit %d", info.Size(), maxRecordBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var w wireScan
	if err := json.Unmarshal(data, &w); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	sc := fromWire(&w)
	if sc.ID == "" {
		sc.ID = id
	}
	return sc, nil
}
