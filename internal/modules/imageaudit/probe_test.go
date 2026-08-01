package imageaudit

import (
	"io/fs"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

func TestProbeFilesClassifiesSurface(t *testing.T) {
	files := []*oci.File{
		{Path: "bin/sh", Mode: 0o755},
		{Path: "usr/bin/bash", Mode: 0o755},
		{Path: "usr/bin/apt-get", Mode: 0o755},
		{Path: "usr/bin/sudo", Mode: fs.FileMode(0o4755)},   // setuid
		{Path: "usr/bin/passwd", Mode: fs.FileMode(0o4755)}, // setuid
		{Path: "usr/bin/wall", Mode: fs.FileMode(0o2755)},   // setgid
		{Path: "app/sh", Mode: 0o755},                       // NOT in a bin dir: not a shell
		{Path: "etc/config", Mode: 0o644},
	}
	p := probeFiles(files)

	if len(p.shells) != 2 { // bin/sh + usr/bin/bash, but not app/sh
		t.Errorf("shells = %v, want [bash sh]", p.shells)
	}
	if len(p.pkgMgrs) != 1 || p.pkgMgrs[0] != "apt-get" {
		t.Errorf("pkgMgrs = %v, want [apt-get]", p.pkgMgrs)
	}
	if p.setuidN != 2 {
		t.Errorf("setuidN = %d, want 2", p.setuidN)
	}
	if p.setgidN != 1 {
		t.Errorf("setgidN = %d, want 1", p.setgidN)
	}
}

// TestSetuidLowBitDetection guards the trap that internal/oci stores the raw
// Unix mode in fs.FileMode without setting fs.ModeSetuid: a naive fs.ModeSetuid
// check would miss every setuid binary. This asserts we read the low bits.
func TestSetuidLowBitDetection(t *testing.T) {
	f := &oci.File{Path: "usr/bin/su", Mode: fs.FileMode(0o4755)}
	if f.Mode&fs.ModeSetuid != 0 {
		t.Fatal("precondition: oci mode should NOT carry the fs.ModeSetuid flag")
	}
	if p := probeFiles([]*oci.File{f}); p.setuidN != 1 {
		t.Errorf("setuid via low bits not detected: setuidN = %d", p.setuidN)
	}
}

func TestProbeDistrolessIsEmpty(t *testing.T) {
	p := probeFiles([]*oci.File{
		{Path: "app/server", Mode: 0o755},
		{Path: "etc/passwd", Mode: 0o644},
	})
	if len(p.shells) != 0 || len(p.pkgMgrs) != 0 || p.setuidN != 0 {
		t.Errorf("distroless-like tree should have no surface, got %+v", p)
	}
}

func TestSecretEnv(t *testing.T) {
	cases := []struct {
		key, value string
		want       bool
	}{
		{"DB_PASSWORD", "hunter2", true},                  // key match + value
		{"API_TOKEN", "abc", true},                        // key match + value
		{"PASSWORD", "", false},                           // key match but empty value declares nothing
		{"HOME", "/root", false},                          // innocuous
		{"INNOCENT", "AKIAIOSFODNN7EXAMPLE", true},        // value shape (AWS) despite innocuous key
		{"X", "ghp_0123456789abcdefghijklmnopqrst", true}, // GitHub token by shape
	}
	for _, c := range cases {
		got, _ := secretEnv(c.key, c.value)
		if got != c.want {
			t.Errorf("secretEnv(%q,%q) = %v, want %v", c.key, c.value, got, c.want)
		}
	}
}

func TestSplitEnv(t *testing.T) {
	if k, v := splitEnv("FOO=bar=baz"); k != "FOO" || v != "bar=baz" {
		t.Errorf("splitEnv split at wrong '=': %q,%q", k, v)
	}
	if k, v := splitEnv("BARE"); k != "BARE" || v != "" {
		t.Errorf("bare key = %q,%q, want BARE,''", k, v)
	}
}
