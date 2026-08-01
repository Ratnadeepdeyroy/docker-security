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

func TestSupports(t *testing.T) {
	m := New()
	if !m.Supports(engine.TargetImage) || !m.Supports(engine.TargetFilesystem) {
		t.Errorf("sbom module should support image and filesystem targets")
	}
	if m.Supports(engine.TargetDockerfile) {
		t.Errorf("sbom module should not support dockerfile targets")
	}
}

func TestAnalyzeEmitsSummary(t *testing.T) {
	m := New()
	findings, err := m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetImage,
		Location: fixtureImage(t),
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	var summary *engine.Finding
	for i := range findings {
		if findings[i].RuleID == "DS-RAT-SBOM-001" {
			summary = &findings[i]
		}
		if findings[i].Severity > engine.SeverityInfo {
			t.Errorf("sbom findings must be INFO (gating-neutral); got %s for %s", findings[i].Severity, findings[i].RuleID)
		}
	}
	if summary == nil {
		t.Fatalf("expected a DS-RAT-SBOM-001 summary finding; got %+v", findings)
	}
	if summary.Metadata["components"] == "" || summary.Metadata["components"] == "0" {
		t.Errorf("summary should report a non-zero component count, got %q", summary.Metadata["components"])
	}
	if summary.Metadata["distro"] != "alpine 3.19.1" {
		t.Errorf("summary distro = %q", summary.Metadata["distro"])
	}
}

// fixtureImage writes a minimal alpine docker-save image tar and returns its path.
func fixtureImage(t *testing.T) string {
	t.Helper()
	tarOf := func(files map[string][]byte) []byte {
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
	layer := tarOf(map[string][]byte{
		"etc/os-release":       []byte("ID=alpine\nVERSION_ID=3.19.1\n"),
		"lib/apk/db/installed": []byte("P:musl\nV:1.2.4-r2\nA:x86_64\nL:MIT\n\n"),
	})
	manifest, _ := json.Marshal([]struct {
		Config   string
		RepoTags []string
		Layers   []string
	}{{Config: "config.json", RepoTags: []string{"alpine:3.19"}, Layers: []string{"layer.tar"}}})
	img := tarOf(map[string][]byte{
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
