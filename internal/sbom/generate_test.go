package sbom

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// tarBytes builds a tar archive from a path->contents map.
func tarBytes(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fixtureImagePath writes a docker-save image tar with a single layer holding an
// alpine package DB plus npm and python metadata, and returns its path.
func fixtureImagePath(t *testing.T) string {
	t.Helper()
	layer := tarBytes(t, map[string][]byte{
		"etc/os-release":                         []byte("ID=alpine\nVERSION_ID=3.19.1\n"),
		"lib/apk/db/installed":                   []byte("P:musl\nV:1.2.4-r2\nA:x86_64\nL:MIT\n\nP:busybox\nV:1.36.1-r5\nA:x86_64\nL:GPL-2.0-only\n\n"),
		"app/node_modules/left-pad/package.json": []byte(`{"name":"left-pad","version":"1.3.0","license":"WTFPL"}`),
		"usr/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA": []byte("Name: requests\nVersion: 2.31.0\nLicense: Apache-2.0\n\n"),
	})
	manifest, _ := json.Marshal([]struct {
		Config   string
		RepoTags []string
		Layers   []string
	}{{Config: "config.json", RepoTags: []string{"fixture:latest"}, Layers: []string{"layer.tar"}}})
	img := tarBytes(t, map[string][]byte{
		"manifest.json": manifest,
		"config.json":   []byte("{}"),
		"layer.tar":     layer,
	})
	p := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(p, img, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGenerateFullImage(t *testing.T) {
	target := &engine.Target{Type: engine.TargetImage, Location: fixtureImagePath(t)}
	doc, err := Generate(context.Background(), target)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if doc.Source.Distro != "alpine 3.19.1" {
		t.Errorf("distro = %q, want alpine 3.19.1", doc.Source.Distro)
	}
	if doc.Source.Name != "fixture:latest" {
		t.Errorf("source name = %q, want fixture:latest", doc.Source.Name)
	}
	names := byName(doc.Components)
	for _, want := range []string{"musl", "busybox", "left-pad", "requests"} {
		if _, ok := names[want]; !ok {
			t.Errorf("expected component %q in SBOM; got %v", want, keysOf(names))
		}
	}
	// Cross-ecosystem coverage: OS + two language ecosystems.
	if names["musl"].Type != TypeOS {
		t.Errorf("musl should be an OS component")
	}
	if names["requests"].PURL != "pkg:pypi/requests@2.31.0" {
		t.Errorf("requests PURL = %q", names["requests"].PURL)
	}
}

func TestGenerateIsDeterministic(t *testing.T) {
	p := fixtureImagePath(t)
	target := &engine.Target{Type: engine.TargetImage, Location: p}
	a, err := Generate(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	ab, _ := Marshal(a, FormatCycloneDX, fixtureMeta())
	bb, _ := Marshal(b, FormatCycloneDX, fixtureMeta())
	if string(ab) != string(bb) {
		t.Errorf("Generate over the same image is not byte-stable")
	}
}

func TestGenerateFullImageGolden(t *testing.T) {
	target := &engine.Target{Type: engine.TargetImage, Location: fixtureImagePath(t)}
	doc, err := Generate(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Marshal(doc, FormatCycloneDX, fixtureMeta())
	if err != nil {
		t.Fatal(err)
	}
	compareGolden(t, "image.cdx.json", got)
}

// compareGolden compares got against testdata/name, materializing the file when
// missing or when -update is set.
func compareGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		_ = os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		_ = os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Errorf("output differs from golden %s (run: go test ./internal/sbom -update)", path)
	}
}

func keysOf(m map[string]Component) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
