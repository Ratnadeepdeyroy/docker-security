package license

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
		t.Errorf("license module should support image and filesystem targets")
	}
	if m.Supports(engine.TargetDockerfile) {
		t.Errorf("license module should not support dockerfile targets")
	}
}

func TestNoPolicyIsInert(t *testing.T) {
	m := New()
	findings, err := m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetImage,
		Location: fixtureImage(t, "GPL-3.0-only"),
		Metadata: map[string]string{}, // no license.* keys
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("module must be inert without a policy; got %d findings: %+v", len(findings), findings)
	}
}

func TestDenyClassFlagsCopyleftPackage(t *testing.T) {
	m := New()
	findings, err := m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetImage,
		Location: fixtureImage(t, "GPL-3.0-only"),
		Metadata: map[string]string{"license.deny-classes": "strong-copyleft"},
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	var got *engine.Finding
	for i := range findings {
		if findings[i].Metadata["component"] == "copyleftpkg" {
			got = &findings[i]
		}
	}
	if got == nil {
		t.Fatalf("expected a DS-RAT-LIC finding for the GPL package; got %+v", findings)
	}
	if got.RuleID != "DS-RAT-LIC-001" {
		t.Errorf("rule id = %s, want DS-RAT-LIC-001 (denied)", got.RuleID)
	}
	if got.Severity != engine.SeverityHigh {
		t.Errorf("default license-deny severity = %s, want high", got.Severity)
	}
	if got.Metadata["license_class"] != "strong-copyleft" {
		t.Errorf("license_class = %q, want strong-copyleft", got.Metadata["license_class"])
	}
}

func TestAllowlistFlagsOffPolicyPackage(t *testing.T) {
	m := New()
	findings, err := m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetImage,
		Location: fixtureImage(t, "GPL-3.0-only"),
		Metadata: map[string]string{"license.allow": "MIT,Apache-2.0"},
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	// musl is MIT (allowed); copyleftpkg is GPL (not allowed) → exactly one finding.
	if len(findings) != 1 || findings[0].RuleID != "DS-RAT-LIC-002" {
		t.Fatalf("allowlist should flag only the GPL package as not-in-allowlist; got %+v", findings)
	}
}

func TestSeverityOverride(t *testing.T) {
	m := New()
	findings, _ := m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetImage,
		Location: fixtureImage(t, "GPL-3.0-only"),
		Metadata: map[string]string{"license.deny-classes": "strong-copyleft", "license.severity": "critical"},
	})
	if len(findings) == 0 || findings[0].Severity != engine.SeverityCritical {
		t.Fatalf("severity override to critical not honored; got %+v", findings)
	}
}

// fixtureImage writes an alpine docker-save image with an MIT package (musl) and
// a second package carrying the supplied license, and returns its path.
func fixtureImage(t *testing.T, secondLicense string) string {
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
	apkdb := "P:musl\nV:1.2.4-r2\nA:x86_64\nL:MIT\n\n" +
		"P:copyleftpkg\nV:1.0.0-r0\nA:x86_64\nL:" + secondLicense + "\n\n"
	layer := tarOf(map[string][]byte{
		"etc/os-release":       []byte("ID=alpine\nVERSION_ID=3.19.1\n"),
		"lib/apk/db/installed": []byte(apkdb),
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
