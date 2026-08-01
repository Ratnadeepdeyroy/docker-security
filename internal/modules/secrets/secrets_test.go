package secrets

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

var update = flag.Bool("update", false, "regenerate golden files")

// --- Fixture: a multi-layer docker-save image with seeded secrets -----------
//
// The image plants a secret in every place the scanner must reach:
//   - layer 0: a GitHub token in app/config.yaml, OVERWRITTEN by a clean copy
//     in layer 2 (so the token survives only in the superseded layer);
//   - layer 1: an AWS access key in etc/secret.env, WHITEOUT-DELETED in layer 2;
//   - layer 1: a live database URI in srv/db.conf (ships in the final image);
//   - config env: a Django secret key;
//   - build history: an AWS secret access key on an ENV line.
// A benign UUID in app/main.py must produce nothing.

// seededSecrets are the raw values planted in the fixture. The test asserts that
// none of them ever appears in the module's output.
var seededSecrets = []string{
	"ghp_0123456789abcdefghijklmnopqrstuvwxyz",
	"AKIAIOSFODNN7EXAMPLE",
	"Tr0ub4dor3xyz",
	"k7Jd9fLp2Qw8zXcV3bNm5tYr1sAe6uHi",
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

func fixtureImagePath(t *testing.T) string {
	t.Helper()

	gz := func(files map[string][]byte) []byte {
		var raw bytes.Buffer
		tw := tar.NewWriter(&raw)
		for name, data := range files {
			flag := byte(tar.TypeReg)
			if strings.HasPrefix(filepath.Base(name), ".wh.") {
				// A whiteout is a zero-length regular file in the layer tar.
				data = nil
			}
			_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: flag})
			_, _ = tw.Write(data)
		}
		_ = tw.Close()
		var zbuf bytes.Buffer
		zw := gzip.NewWriter(&zbuf)
		_, _ = zw.Write(raw.Bytes())
		_ = zw.Close()
		return zbuf.Bytes()
	}

	layer0 := gz(map[string][]byte{
		"app/config.yaml": []byte("github_token: ghp_0123456789abcdefghijklmnopqrstuvwxyz\n"),
		"app/main.py":     []byte("request_id = \"550e8400-e29b-41d4-a716-446655440000\"\n"),
	})
	layer1 := gz(map[string][]byte{
		"srv/db.conf":    []byte("DATABASE_URL=postgres://admin:Tr0ub4dor3xyz@db:5432/app\n"),
		"etc/secret.env": []byte("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"),
	})
	layer2 := gz(map[string][]byte{
		"app/config.yaml":    []byte("github_token: redacted\n"),
		"etc/.wh.secret.env": nil,
	})

	config := []byte(`{
		"config": {"Env": ["PATH=/usr/local/bin", "DJANGO_SECRET_KEY=k7Jd9fLp2Qw8zXcV3bNm5tYr1sAe6uHi"]},
		"history": [
			{"created_by": "ADD file:abc in /"},
			{"created_by": "ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
		]
	}`)

	manifest, _ := json.Marshal([]struct {
		Config   string
		RepoTags []string
		Layers   []string
	}{{
		Config:   "config.json",
		RepoTags: []string{"example/leaky:latest"},
		Layers:   []string{"layer-0.tar", "layer-1.tar", "layer-2.tar"},
	}})

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write := func(name string, data []byte) {
		_ = tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(data)
	}
	write("config.json", config)
	write("layer-0.tar", layer0)
	write("layer-1.tar", layer1)
	write("layer-2.tar", layer2)
	write("manifest.json", manifest)
	_ = tw.Close()

	p := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write fixture image: %v", err)
	}
	return p
}

func TestSupports(t *testing.T) {
	m := New()
	for _, ty := range []engine.TargetType{engine.TargetImage, engine.TargetFilesystem, engine.TargetDockerfile} {
		if !m.Supports(ty) {
			t.Errorf("secrets module should support %s", ty)
		}
	}
	if m.Supports(engine.TargetRegistry) {
		t.Error("secrets module should not claim registry targets")
	}
}

func TestAnalyzeImageLayerAware(t *testing.T) {
	m := New()
	findings, err := m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetImage,
		Location: fixtureImagePath(t),
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	byID := map[string]engine.Finding{}
	for _, f := range findings {
		byID[f.RuleID] = f
	}

	// GitHub token: overwritten in layer 2, must be found in the deleted layer 0.
	gh, ok := byID["DS-RAT-SEC-004"]
	if !ok || gh.Metadata["deleted"] != "true" || gh.Metadata["layer_index"] != "0" {
		t.Errorf("github token deleted-layer finding wrong: %+v", gh)
	}
	// AWS access key: whiteout-deleted, must be found in layer 1.
	aws, ok := byID["DS-RAT-SEC-001"]
	if !ok || aws.Metadata["deleted"] != "true" || aws.Metadata["layer_index"] != "1" {
		t.Errorf("aws key deleted-layer finding wrong: %+v", aws)
	}
	// DB URI ships live.
	if db, ok := byID["DS-RAT-SEC-013"]; !ok || db.Metadata["deleted"] != "false" {
		t.Errorf("db uri live finding wrong: %+v", db)
	}
	// Config env + build history secrets.
	if _, ok := byID["DS-RAT-SEC-014"]; !ok {
		t.Error("expected config-env secret DS-RAT-SEC-014")
	}
	if _, ok := byID["DS-RAT-SEC-002"]; !ok {
		t.Error("expected build-history AWS secret DS-RAT-SEC-002")
	}

	// The single most important safety property: no raw secret value anywhere.
	blob, _ := json.Marshal(findings)
	for _, sec := range seededSecrets {
		if bytes.Contains(blob, []byte(sec)) {
			t.Errorf("output leaked a raw secret value: %q", sec)
		}
	}
}

// TestAnalyzeGolden pins the full projected output so determinism regressions
// surface as a diff. Regenerate with: go test ./internal/modules/secrets -update
func TestAnalyzeGolden(t *testing.T) {
	m := New()
	findings, err := m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetImage,
		Location: fixtureImagePath(t),
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	got, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	compareGolden(t, "image_findings.json", got)
}

func TestDockerfileScanning(t *testing.T) {
	df := []byte("FROM alpine:3.19\n" +
		"ENV STRIPE_KEY=sk_live_0123456789ab" + "cdefghijklmn\n" +
		"RUN echo done\n")
	m := New()
	findings, err := m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetDockerfile,
		Location: "Dockerfile",
		Content:  df,
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	var found bool
	for _, f := range findings {
		if f.RuleID == "DS-RAT-SEC-009" {
			found = true
			if f.Metadata["source"] != "dockerfile" {
				t.Errorf("dockerfile finding source = %q", f.Metadata["source"])
			}
		}
	}
	if !found {
		t.Errorf("expected Stripe key DS-RAT-SEC-009 in Dockerfile, got %+v", findings)
	}
}

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
		t.Errorf("output differs from golden %s (run: go test ./internal/modules/secrets -update)", path)
	}
}
