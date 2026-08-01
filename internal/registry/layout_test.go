package registry

import (
	"os"
	"path/filepath"
	"testing"
)

// TestManifestDigestFromLayout builds a tiny OCI layout on disk and confirms we
// read back the manifest digest recorded in index.json — the offline digest the
// verify path needs.
func TestManifestDigestFromLayout(t *testing.T) {
	dir := t.TempDir()
	manifest := []byte(`{"schemaVersion":2,"mediaType":"` + MediaTypeOCIManifest + `","config":{},"layers":[]}`)
	manDigest := Digest(manifest)

	// Write the manifest blob.
	blobDir := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, hexPart, _ := splitOnce(manDigest, ':')
	if err := os.WriteFile(filepath.Join(blobDir, hexPart), manifest, 0o644); err != nil {
		t.Fatal(err)
	}

	// index.json points at it.
	index := `{"schemaVersion":2,"manifests":[{"mediaType":"` + MediaTypeOCIManifest + `","digest":"` + manDigest + `","size":` + itoa(len(manifest)) + `}]}`
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(index), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := ManifestDigestFromLayout(dir)
	if err != nil {
		t.Fatalf("ManifestDigestFromLayout: %v", err)
	}
	if got != manDigest {
		t.Errorf("digest = %s, want %s", got, manDigest)
	}
}

func TestManifestDigestFromLayoutErrors(t *testing.T) {
	if _, err := ManifestDigestFromLayout(t.TempDir()); err == nil {
		t.Error("expected error for a directory with no index.json")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
