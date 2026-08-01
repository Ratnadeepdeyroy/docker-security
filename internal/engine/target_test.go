package engine

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// buildDockerSaveTar assembles a minimal `docker save`-shaped tar (a
// manifest.json plus its referenced config blob, no layers needed for this
// test) so Target.Image can exercise a real oci.Load.
func buildDockerSaveTar(t *testing.T, repoTag string) []byte {
	t.Helper()
	manifest, err := json.Marshal([]map[string]any{{
		"Config":   "config.json",
		"RepoTags": []string{repoTag},
		"Layers":   []string{},
	}})
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	files := map[string][]byte{
		"manifest.json": manifest,
		"config.json":   []byte("{}"),
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(data)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("write header %q: %v", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("write body %q: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

// TestTargetImageLoadsOnce verifies Target.Image memoizes the load: the
// second call must return the exact same *oci.Image (pointer identity) and
// must not touch the filesystem again. We prove "no second load" by
// corrupting Location after the first call — if Image() reloaded, the second
// call would fail (or return a different value); instead it must keep
// serving the cached result.
func TestTargetImageLoadsOnce(t *testing.T) {
	p := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(p, buildDockerSaveTar(t, "fixture:latest"), 0o644); err != nil {
		t.Fatalf("write temp image: %v", err)
	}

	target := &Target{Type: TargetImage, Location: p}

	img1, err := target.Image()
	if err != nil {
		t.Fatalf("first Image() call: %v", err)
	}
	if len(img1.RepoTags) != 1 || img1.RepoTags[0] != "fixture:latest" {
		t.Fatalf("img1.RepoTags = %v, want [fixture:latest]", img1.RepoTags)
	}

	// Corrupt the on-disk archive. A second real load would now fail (or, if
	// it happened to still parse, would be a distinct *oci.Image). Since
	// Image() must serve the cached result instead, this proves the load ran
	// exactly once.
	if err := os.WriteFile(p, []byte("not a valid image archive"), 0o644); err != nil {
		t.Fatalf("corrupt temp image: %v", err)
	}

	img2, err := target.Image()
	if err != nil {
		t.Fatalf("second Image() call: %v (cache was not used; image was reloaded from corrupted file)", err)
	}
	if img1 != img2 {
		t.Fatalf("second Image() call returned a different *oci.Image pointer; want the cached instance")
	}
}

// TestTargetImageCachesLoadError verifies that a load failure is also
// memoized: repeated calls return the same error without a second attempt to
// read Location, and never fall back to some other successful result.
func TestTargetImageCachesLoadError(t *testing.T) {
	p := filepath.Join(t.TempDir(), "missing.tar")
	target := &Target{Type: TargetImage, Location: p}

	img1, err1 := target.Image()
	if err1 == nil {
		t.Fatalf("first Image() call: want error for missing file, got nil (img=%v)", img1)
	}

	// Now make Location resolve to a valid image. If Image() re-ran oci.Load,
	// this second call would succeed with a non-nil image; the memoized
	// version must still return the original error.
	if err := os.WriteFile(p, buildDockerSaveTar(t, "fixture:latest"), 0o644); err != nil {
		t.Fatalf("write temp image: %v", err)
	}

	img2, err2 := target.Image()
	if err2 == nil {
		t.Fatalf("second Image() call: want cached error, got success (img=%v); load ran again instead of using the cache", img2)
	}
	if err1.Error() != err2.Error() {
		t.Fatalf("second Image() call returned a different error: first=%q second=%q", err1, err2)
	}
	if img1 != img2 {
		t.Fatalf("second Image() call returned a different (nil) image pointer than the first")
	}
}
