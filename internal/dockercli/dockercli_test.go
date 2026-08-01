package dockercli

import (
	"context"
	"testing"
)

func TestValidRef(t *testing.T) {
	ok := []string{
		"redis:7-alpine", "postgres:16", "docker.io/library/nginx:1.25",
		"ghcr.io/org/app@sha256:" + repeat("a", 64), "abc123def456", "rockylinux:9",
	}
	bad := []string{
		"", "-rf", "--output=/etc/passwd", "redis;rm -rf /", "a b", "im`age`",
		"$(whoami)", "redis:7 && echo", "\n", "img|cat",
	}
	for _, r := range ok {
		if !ValidRef(r) {
			t.Errorf("ValidRef(%q) = false, want true", r)
		}
	}
	for _, r := range bad {
		if ValidRef(r) {
			t.Errorf("ValidRef(%q) = true, want false (injection/malformed)", r)
		}
	}
}

func TestNormalizeRef(t *testing.T) {
	cases := map[string]string{
		"ubuntu:latest":                            "ubuntu:latest",
		"redis:7-alpine":                           "redis:7-alpine",
		"ghcr.io/org/app:1.2":                      "ghcr.io/org/app:1.2",
		"https://hub.docker.com/_/ubuntu":          "ubuntu",
		"https://hub.docker.com/_/ubuntu?tab=tags": "ubuntu",
		"https://hub.docker.com/r/bitnami/nginx":   "bitnami/nginx",
		"https://ghcr.io/org/app:tag":              "ghcr.io/org/app:tag",
		"http://registry.local:5000/img:1":         "registry.local:5000/img:1",
	}
	for in, want := range cases {
		got, ok := NormalizeRef(in)
		if !ok || got != want {
			t.Errorf("NormalizeRef(%q) = %q,%v; want %q,true", in, got, ok, want)
		}
	}
	// Things that are not references.
	for _, in := range []string{"", "   ", "/tmp/redis.tar", "not a ref", "https://example.com/a page/x"} {
		if got, ok := NormalizeRef(in); ok {
			t.Errorf("NormalizeRef(%q) = %q,true; want not-ok", in, got)
		}
	}
}

// TestSaveRejectsUnsafeRef proves an unsafe reference never reaches docker,
// regardless of whether docker is installed.
func TestSaveRejectsUnsafeRef(t *testing.T) {
	if err := Save(context.Background(), "--output=/tmp/x", "/tmp/out.tar"); err == nil {
		t.Error("Save must reject an unsafe reference before exec")
	}
}

// TestImagesWhenAvailable is a light integration check: it runs only where a
// docker binary exists, and just asserts the call does not error and refs are
// well-formed. It is skipped in CI/hosts without docker.
func TestImagesWhenAvailable(t *testing.T) {
	if !Available() {
		t.Skip("docker not available")
	}
	imgs, err := Images(context.Background())
	if err != nil {
		t.Fatalf("Images: %v", err)
	}
	for _, im := range imgs {
		if im.Ref != "" && !ValidRef(im.Ref) {
			t.Errorf("detected image has an unexpectedly unsafe ref: %q", im.Ref)
		}
	}
}

func repeat(s string, n int) string {
	out := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, s[0])
	}
	return string(out)
}
