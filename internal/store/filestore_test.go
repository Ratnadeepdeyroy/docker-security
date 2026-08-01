package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

func TestFileStore_PersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	id, err := s.Put(scan("api", 1,
		[]Component{{Name: "openssl", Version: "3.0.1"}},
		f("DS-RAT-VULN-001", engine.SeverityHigh)))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Reopen a fresh store over the same dir: the record must reload and remain queryable.
	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, ok := s2.Get(id)
	if !ok {
		t.Fatalf("scan %s missing after reopen", id)
	}
	if got.Image != "api" || len(got.Components) != 1 {
		t.Errorf("reloaded scan corrupted: %+v", got)
	}
	if hits := s2.QueryComponent(ComponentQuery{Name: "openssl"}); len(hits) != 1 {
		t.Errorf("blast-radius query broke after reload: %+v", hits)
	}
}

func TestFileStore_WritesAtomicValidJSON(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	id, _ := s.Put(scan("web", 2, nil, f("DS-RAT-DF-001", engine.SeverityLow)))

	data, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("persisted file is not valid JSON: %v", err)
	}
	if back["id"] != id {
		t.Errorf("persisted id = %v, want %q", back["id"], id)
	}
	// No leftover temp files.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestFileStore_SkipsHostileRecordsOnLoad(t *testing.T) {
	dir := t.TempDir()
	// A valid record, plus three hostile files that must be skipped without
	// killing the load of the good one.
	good, _ := Open(dir)
	goodID, _ := good.Put(scan("api", 1, nil, f("DS-RAT-X-1", engine.SeverityLow)))

	// (a) garbage JSON under a validly-shaped id name.
	os.WriteFile(filepath.Join(dir, "aaaaaaaaaaaaaaaa.json"), []byte("{not json"), 0o644)
	// (b) unsafe filename (path-traversal flavored) — must never be treated as an id.
	os.WriteFile(filepath.Join(dir, "..evil.json"), []byte("{}"), 0o644)
	// (c) oversized record.
	big := make([]byte, maxRecordBytes+1)
	os.WriteFile(filepath.Join(dir, "bbbbbbbbbbbbbbbb.json"), big, 0o644)

	s, err := Open(dir)
	if err == nil {
		t.Fatal("expected a non-nil error reporting skipped records")
	}
	if !strings.Contains(err.Error(), "skipped") {
		t.Errorf("error should mention skipped records: %v", err)
	}
	// The good record still loaded.
	if _, ok := s.Get(goodID); !ok {
		t.Errorf("good record %s did not load alongside hostile files", goodID)
	}
	if s.Len() != 1 {
		t.Errorf("want exactly 1 valid record loaded, got %d", s.Len())
	}
}

func TestFileStore_RefusesUnsafeIDOnSave(t *testing.T) {
	dir := t.TempDir()
	b := &fileBackend{dir: dir}
	// A crafted id that would traverse out of the store dir must be refused.
	err := b.save(&Scan{ID: "../../etc/passwd", Image: "x"})
	if err == nil {
		t.Fatal("expected save to refuse an unsafe id")
	}
}

// TestGolden_BlastRadius pins the blast-radius query output byte-for-byte so a
// regression in ordering or field selection is caught. Regenerate with -update.
func TestGolden_BlastRadius(t *testing.T) {
	s := seed(t)
	got := s.QueryComponent(ComponentQuery{Name: "openssl"})
	out, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out = append(out, '\n')
	golden := filepath.Join("testdata", "blast_radius_openssl.json")
	if *update {
		if err := os.WriteFile(golden, out, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if string(out) != string(want) {
		t.Errorf("blast-radius output drifted from golden:\n got:\n%s\nwant:\n%s", out, want)
	}
}
