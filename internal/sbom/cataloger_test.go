package sbom

import (
	"debug/buildinfo"
	"encoding/base64"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// runCataloger builds a tree from files, detects the distro, and runs c.
func runCataloger(t *testing.T, c Cataloger, files map[string][]byte) []Component {
	t.Helper()
	tree := oci.TreeFromMap(files)
	comps, _, err := c.Catalog(tree, detectDistro(tree))
	if err != nil {
		t.Fatalf("%s.Catalog: %v", c.Name(), err)
	}
	return comps
}

// byName indexes components by their name.
func byName(comps []Component) map[string]Component {
	m := map[string]Component{}
	for _, c := range comps {
		m[c.Name] = c
	}
	return m
}

func TestAPKCataloger(t *testing.T) {
	sha1 := make([]byte, 20)
	for i := range sha1 {
		sha1[i] = byte(i)
	}
	installed := "P:musl\nV:1.2.4-r2\nA:x86_64\nL:MIT\nC:Q1" + base64.StdEncoding.EncodeToString(sha1) + "\n\n" +
		"P:busybox\nV:1.36.1-r5\nA:x86_64\nL:GPL-2.0-only\n\n"
	comps := runCataloger(t, apkCataloger{}, map[string][]byte{
		"etc/os-release":       []byte("ID=alpine\nVERSION_ID=3.19.1\n"),
		"lib/apk/db/installed": []byte(installed),
	})
	got := byName(comps)
	musl, ok := got["musl"]
	if !ok {
		t.Fatalf("musl not cataloged; got %v", comps)
	}
	if want := "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=alpine-3.19.1"; musl.PURL != want {
		t.Errorf("musl PURL = %q, want %q", musl.PURL, want)
	}
	if len(musl.Licenses) != 1 || musl.Licenses[0].ID != "MIT" {
		t.Errorf("musl license = %v, want [{ID:MIT}]", musl.Licenses)
	}
	if len(musl.Hashes) != 1 || musl.Hashes[0].Algorithm != "SHA-1" {
		t.Errorf("musl hash = %v, want one SHA-1", musl.Hashes)
	}
	if _, ok := got["busybox"]; !ok {
		t.Errorf("busybox not cataloged")
	}
}

func TestDpkgCatalogerSkipsNotInstalled(t *testing.T) {
	status := "Package: bash\nStatus: install ok installed\nVersion: 5.1-2+deb11u1\nArchitecture: amd64\n\n" +
		"Package: removed-pkg\nStatus: deinstall ok config-files\nVersion: 1.0\nArchitecture: amd64\n\n"
	comps := runCataloger(t, dpkgCataloger{}, map[string][]byte{
		"etc/os-release":      []byte(`ID=debian` + "\n" + `VERSION_ID="11"` + "\n"),
		"var/lib/dpkg/status": []byte(status),
	})
	got := byName(comps)
	bash, ok := got["bash"]
	if !ok {
		t.Fatalf("bash not cataloged; got %v", comps)
	}
	if want := "pkg:deb/debian/bash@5.1-2+deb11u1?arch=amd64&distro=debian-11"; bash.PURL != want {
		t.Errorf("bash PURL = %q, want %q", bash.PURL, want)
	}
	if _, ok := got["removed-pkg"]; ok {
		t.Errorf("removed-pkg (not installed) should be skipped")
	}
}

func TestNpmCatalogerScopedAndPlain(t *testing.T) {
	comps := runCataloger(t, npmCataloger{}, map[string][]byte{
		"app/node_modules/left-pad/package.json":     []byte(`{"name":"left-pad","version":"1.3.0","license":"WTFPL"}`),
		"app/node_modules/@scope/thing/package.json": []byte(`{"name":"@scope/thing","version":"2.0.0"}`),
	})
	got := byName(comps)
	lp, ok := got["left-pad"]
	if !ok {
		t.Fatalf("left-pad not cataloged; got %v", comps)
	}
	if lp.PURL != "pkg:npm/left-pad@1.3.0" {
		t.Errorf("left-pad PURL = %q", lp.PURL)
	}
	scoped, ok := got["@scope/thing"]
	if !ok {
		t.Fatalf("@scope/thing not cataloged")
	}
	if scoped.PURL != "pkg:npm/%40scope/thing@2.0.0" {
		t.Errorf("@scope/thing PURL = %q, want pkg:npm/%%40scope/thing@2.0.0", scoped.PURL)
	}
}

func TestPipCataloger(t *testing.T) {
	metadata := "Metadata-Version: 2.1\nName: Requests\nVersion: 2.31.0\nLicense: Apache-2.0\n\nbody text\n"
	comps := runCataloger(t, pipCataloger{}, map[string][]byte{
		"usr/lib/python3.11/site-packages/requests-2.31.0.dist-info/METADATA": []byte(metadata),
	})
	if len(comps) != 1 {
		t.Fatalf("expected 1 python component, got %d: %v", len(comps), comps)
	}
	c := comps[0]
	// PEP 503 normalization lowercases the name in the PURL.
	if c.PURL != "pkg:pypi/requests@2.31.0" {
		t.Errorf("requests PURL = %q, want pkg:pypi/requests@2.31.0", c.PURL)
	}
	if len(c.Licenses) != 1 || c.Licenses[0].ID != "Apache-2.0" {
		t.Errorf("requests license = %v", c.Licenses)
	}
}

func TestGolangCatalogerGoMod(t *testing.T) {
	gomod := "module github.com/example/app\n\ngo 1.22\n\nrequire (\n\tgithub.com/gorilla/mux v1.8.0 // indirect\n\tgolang.org/x/sys v0.1.0\n)\n\nrequire example.com/single v1.0.0\n"
	comps := runCataloger(t, golangCataloger{}, map[string][]byte{"src/go.mod": []byte(gomod)})
	got := byName(comps)
	mux, ok := got["github.com/gorilla/mux"]
	if !ok {
		t.Fatalf("gorilla/mux not cataloged; got %v", comps)
	}
	if mux.PURL != "pkg:golang/github.com/gorilla/mux@v1.8.0" {
		t.Errorf("mux PURL = %q", mux.PURL)
	}
	if _, ok := got["golang.org/x/sys"]; !ok {
		t.Errorf("golang.org/x/sys not cataloged from require block")
	}
	if _, ok := got["example.com/single"]; !ok {
		t.Errorf("single-line require not cataloged")
	}
	if app, ok := got["github.com/example/app"]; !ok || app.Type != TypeApp {
		t.Errorf("main module should be cataloged as application, got %+v", app)
	}
}

// buildFixtureBinary compiles a tiny, dependency-free Go module into a real
// executable in an isolated temp module, so tests can exercise
// debug/buildinfo end to end without any network access or go.sum changes.
//
// It builds the package by its import path ("."), not by passing the source
// file path to `go build`: building by file path produces a
// "command-line-arguments" binary with no module info attached (verified via
// `go version -m`), which would defeat the point of this fixture.
func buildFixtureBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/fixture\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	bin := filepath.Join(dir, "fixture-bin")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = dir
	cmd.Env = os.Environ()
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fixture binary: %v\n%s", err, out)
	}
	return bin
}

func TestGolangCatalogerBinary(t *testing.T) {
	bin := buildFixtureBinary(t)
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read fixture binary: %v", err)
	}
	comps := runCataloger(t, golangCataloger{}, map[string][]byte{"usr/local/bin/fixture-bin": data})
	got := byName(comps)
	self, ok := got["example.com/fixture"]
	if !ok {
		t.Fatalf("main module not cataloged from binary; got %+v", comps)
	}
	if self.Type != TypeApp {
		t.Errorf("main module type = %q, want %q", self.Type, TypeApp)
	}
	if self.Source != "/usr/local/bin/fixture-bin" {
		t.Errorf("main module source = %q, want /usr/local/bin/fixture-bin", self.Source)
	}
	if self.PURL != "pkg:golang/example.com/fixture@(devel)" {
		t.Errorf("main module PURL = %q, want pkg:golang/example.com/fixture@(devel)", self.PURL)
	}
}

func TestGolangCatalogerSkipsOversizedBinary(t *testing.T) {
	old := maxGoBinarySize
	maxGoBinarySize = 8 // smaller than any real binary, without allocating gigabytes
	t.Cleanup(func() { maxGoBinarySize = old })

	bin := buildFixtureBinary(t)
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read fixture binary: %v", err)
	}
	comps := runCataloger(t, golangCataloger{}, map[string][]byte{"usr/local/bin/fixture-bin": data})
	if len(comps) != 0 {
		t.Fatalf("expected oversized binary to be skipped, got %+v", comps)
	}
}

// TestGolangCatalogerNonGoInput covers files that pass looksLikeExecutable's
// magic-number sniff but aren't real Go binaries, plus a plain text file that
// doesn't match any magic number or go.mod at all. Neither should panic or
// error the scan; both should simply contribute zero components.
func TestGolangCatalogerNonGoInput(t *testing.T) {
	comps := runCataloger(t, golangCataloger{}, map[string][]byte{
		// ELF magic followed by garbage: passes looksLikeExecutable, but
		// debug/buildinfo.Read must fail on it cleanly (fromBinary returns nil).
		"usr/local/bin/not-a-real-elf": append([]byte{0x7f, 'E', 'L', 'F'}, []byte("garbage garbage garbage garbage")...),
		// Plain text: no magic number match, and not a go.mod either.
		"usr/share/doc/readme.txt": []byte("just some documentation, nothing binary here\n"),
	})
	if len(comps) != 0 {
		t.Fatalf("non-Go input should yield zero components, got %+v", comps)
	}
}

// TestMaxGoBinarySizeMatchesOCICap locks in that maxGoBinarySize does not
// exceed internal/oci's per-file read cap (maxFileBytes in
// internal/oci/loader.go). If it did, a file between the oci cap and this
// one would pass the size gate with its Data already silently truncated by
// the loader, so buildinfo.Read would be attempted on truncated bytes for
// no benefit (see the comment on maxGoBinarySize).
func TestMaxGoBinarySizeMatchesOCICap(t *testing.T) {
	const ociMaxFileBytes = 256 << 20 // internal/oci/loader.go maxFileBytes
	if maxGoBinarySize > ociMaxFileBytes {
		t.Errorf("maxGoBinarySize = %d exceeds oci's maxFileBytes = %d; files in between would be attempted on truncated data", maxGoBinarySize, ociMaxFileBytes)
	}
}

// TestGolangCatalogerFromBinaryRecoversPanic proves fromBinary's
// defer/recover turns a panic during buildinfo parsing into "skip this file"
// rather than crashing the whole scan. readBuildInfo is substituted with a
// stand-in that panics: every malformed-but-magic-prefixed ELF/Mach-O/PE/Wasm
// input tried against the real debug/buildinfo.Read on this Go toolchain
// failed cleanly with an error rather than panicking (its parsers are
// well-hardened against the malformed inputs tried), so the panic is
// injected via a seam instead — this exercises the exact recover path a
// future stdlib panic (or a not-yet-found malformed input) would hit.
func TestGolangCatalogerFromBinaryRecoversPanic(t *testing.T) {
	old := readBuildInfo
	readBuildInfo = func(io.ReaderAt) (*buildinfo.BuildInfo, error) {
		panic("simulated panic parsing a malformed binary")
	}
	t.Cleanup(func() { readBuildInfo = old })

	// Magic-prefixed garbage: passes looksLikeExecutable's 4-byte sniff, so
	// fromBinary is reached and hits the injected panic.
	data := append([]byte{0x7f, 'E', 'L', 'F'}, []byte("garbage garbage garbage garbage")...)
	comps := runCataloger(t, golangCataloger{}, map[string][]byte{
		"usr/local/bin/panics-while-parsing": data,
	})
	if len(comps) != 0 {
		t.Fatalf("expected zero components when buildinfo parsing panics, got %+v", comps)
	}
}

func TestDetectDistroAlpineFallback(t *testing.T) {
	tree := oci.TreeFromMap(map[string][]byte{"etc/alpine-release": []byte("3.19.1\n")})
	d := detectDistro(tree)
	if d.ID != "alpine" || d.VersionID != "3.19.1" {
		t.Errorf("detectDistro = %+v, want alpine 3.19.1", d)
	}
}
