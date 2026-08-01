package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// buildTar assembles a tar archive from a path->contents map.
func buildTar(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
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

func gzipBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p
}

func TestLoadDockerSaveAppliesWhiteouts(t *testing.T) {
	layer0 := buildTar(t, map[string][]byte{
		"etc/os-release": []byte("ID=alpine\nVERSION_ID=3.19.1\n"),
		"app/keep.txt":   []byte("keep"),
		"app/gone.txt":   []byte("delete me"),
	})
	// Layer 1 whiteouts app/gone.txt (via .wh.) and adds a new file. Gzip it to
	// exercise transparent decompression.
	layer1 := gzipBytes(t, buildTar(t, map[string][]byte{
		"app/.wh.gone.txt": {},
		"app/new.txt":      []byte("new"),
	}))
	manifest, _ := json.Marshal([]dockerManifest{{
		Config:   "config.json",
		RepoTags: []string{"fixture:latest"},
		Layers:   []string{"layer0.tar", "layer1.tar"},
	}})
	img := buildTar(t, map[string][]byte{
		"manifest.json": manifest,
		"config.json":   []byte("{}"),
		"layer0.tar":    layer0,
		"layer1.tar":    layer1,
	})

	loaded, err := Load(writeTemp(t, img))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := loaded.RepoTags; len(got) != 1 || got[0] != "fixture:latest" {
		t.Errorf("RepoTags = %v, want [fixture:latest]", got)
	}
	tree := loaded.Flatten()
	if _, ok := tree.Get("etc/os-release"); !ok {
		t.Errorf("etc/os-release missing from flattened tree")
	}
	if _, ok := tree.Get("app/keep.txt"); !ok {
		t.Errorf("app/keep.txt should survive")
	}
	if _, ok := tree.Get("app/new.txt"); !ok {
		t.Errorf("app/new.txt from layer 1 missing")
	}
	if _, ok := tree.Get("app/gone.txt"); ok {
		t.Errorf("app/gone.txt should have been whiteout-deleted")
	}
}

func TestFlattenOpaqueWhiteout(t *testing.T) {
	layer0 := buildTar(t, map[string][]byte{
		"data/a.txt": []byte("a"),
		"data/b.txt": []byte("b"),
	})
	layer1 := buildTar(t, map[string][]byte{
		"data/.wh..wh..opq": {},
		"data/c.txt":        []byte("c"),
	})
	manifest, _ := json.Marshal([]dockerManifest{{Config: "c.json", Layers: []string{"l0", "l1"}}})
	img := buildTar(t, map[string][]byte{
		"manifest.json": manifest,
		"c.json":        []byte("{}"),
		"l0":            layer0,
		"l1":            layer1,
	})
	loaded, err := Load(writeTemp(t, img))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	tree := loaded.Flatten()
	for _, gone := range []string{"data/a.txt", "data/b.txt"} {
		if _, ok := tree.Get(gone); ok {
			t.Errorf("%s should be removed by opaque whiteout", gone)
		}
	}
	if _, ok := tree.Get("data/c.txt"); !ok {
		t.Errorf("data/c.txt added in the opaque layer should survive")
	}
}

func TestLoadOCILayoutTar(t *testing.T) {
	layerTar := buildTar(t, map[string][]byte{"etc/hello": []byte("hi")})
	config := []byte(`{"architecture":"amd64","os":"linux"}`)
	blob := func(m map[string][]byte, data []byte) string {
		sum := sha256.Sum256(data)
		digest := "sha256:" + hex.EncodeToString(sum[:])
		m["blobs/sha256/"+hex.EncodeToString(sum[:])] = data
		return digest
	}
	entries := map[string][]byte{"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}`)}
	cfgDigest := blob(entries, config)
	layerDigest := blob(entries, layerTar)
	manifest, _ := json.Marshal(ociManifest{
		Config: ociDescriptor{Digest: cfgDigest, MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{{Digest: layerDigest, MediaType: "application/vnd.oci.image.layer.v1.tar"}},
	})
	manDigest := blob(entries, manifest)
	index, _ := json.Marshal(ociIndex{Manifests: []ociDescriptor{{Digest: manDigest, MediaType: "application/vnd.oci.image.manifest.v1+json"}}})
	entries["index.json"] = index

	loaded, err := Load(writeTemp(t, buildTar(t, entries)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.ConfigDigest != cfgDigest {
		t.Errorf("ConfigDigest = %q, want %q", loaded.ConfigDigest, cfgDigest)
	}
	tree := loaded.Flatten()
	f, ok := tree.Get("etc/hello")
	if !ok || string(f.Data) != "hi" {
		t.Errorf("etc/hello not loaded from OCI layer")
	}
}

func TestTreeFromDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "f.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	tree, err := TreeFromDir(dir)
	if err != nil {
		t.Fatalf("TreeFromDir: %v", err)
	}
	if _, ok := tree.Get("sub/f.txt"); !ok {
		t.Errorf("expected sub/f.txt in tree, got %v", tree.Files())
	}
}
