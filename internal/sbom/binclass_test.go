package sbom

import (
	"testing"
)

// TestClassifyBinary is the brief's table: filename-gated, version extracted
// from embedded strings.
func TestClassifyBinary(t *testing.T) {
	cases := []struct {
		base    string
		blob    string
		name    string
		version string
		ok      bool
	}{
		{"python3.9", "xxx3.9.25 (main, Jan  1 2026)yyy", "python", "3.9.25", true},
		{"python3", "nothing here", "", "", false}, // no version string
		{"node", "abc v20.11.1 def", "node", "20.11.1", true},
		{"openssl", "part of OpenSSL 3.5.1 8 Jul 2025", "openssl", "3.5.1", true},
		// The 1.0.2 branch exhausted single-letter patch suffixes (a...z) and
		// continued with two-letter suffixes through the final EOL release,
		// 1.0.2zj; the regex must capture both letters, not just the first.
		{"openssl", "OpenSSL 1.0.2zc 15 Sep 2020", "openssl", "1.0.2zc", true},
		{"busybox", "BusyBox v1.36.1 (2025-01-01)", "busybox", "1.36.1", true},
		// OpenJDK's `java -version` banner reports the version twice: a quoted
		// display form and a build string like "(build 17.0.2+8-86)". Either
		// captures the same base "17.0.2" since the trailing qualifier is
		// only appended when actually present.
		{"java", `openjdk version "17.0.2" 2022-01-18` + "\n" +
			`OpenJDK Runtime Environment (build 17.0.2+8-86)`, "java", "17.0.2", true},
		// Legacy Java 8 embeds its version as "1.8.0_NNN[-bXX]"; "_392" is the
		// only thing that distinguishes this update from ~400 others sharing
		// the identical "1.8.0" base, so it must be retained in the version.
		{"java", `java version "1.8.0_392"` + "\n" +
			`Java(TM) SE Runtime Environment (build 1.8.0_392-b08)`, "java", "1.8.0_392", true},
		// Realistic `perl -v` banner: "5.40.1" appears ~30 chars after "perl",
		// inside "(v5.40.1)".
		{"perl", "This is perl 5, version 40, subversion 1 (v5.40.1)", "perl", "5.40.1", true},
		{"README", "python3.9.25", "", "", false}, // filename not a known runtime

		// Shared-library detection: CPython's real version lives in
		// libpython*.so, not the thin launcher. major.minor comes from the
		// filename, the patch level from a bare embedded string.
		{"libpython3.9.so.1.0", "padding\x003.9.25\x00more", "python", "3.9.25", true},
		{"libpython3.9.so", "junk\x003.9.25\x00junk", "python", "3.9.25", true},
		{"libpython3.12.so", "\x003.12.4\x00", "python", "3.12.4", true},
		// A version string that disagrees with the filename's major.minor must
		// not be adopted; fall back to the filename's major.minor.
		{"libpython3.9.so.1.0", "only \x002.7.18\x00 here, no matching patch", "python", "3.9", true},
		// No major.minor digits in the filename at all: the soClassifier's
		// nameRe can't extract a version, so nothing classifies it even though
		// the contents look right.
		{"libpython.so", "totally 3.9.25 legit", "", "", false},
		// A shared object for a runtime we don't track: no binClassifier or
		// soClassifier name pattern matches it.
		{"libssl.so", "OpenSSL 3.5.1 8 Jul 2025", "", "", false},

		// Filenames are matched case-insensitively.
		{"Python3.9", "xxx3.9.25 (main, Jan  1 2026)yyy", "python", "3.9.25", true},
		{"LIBPYTHON3.9.SO", "junk\x003.9.25\x00junk", "python", "3.9.25", true},
	}
	for _, c := range cases {
		comp, ok := classifyBinary(c.base, []byte(c.blob))
		if ok != c.ok {
			t.Errorf("%s: ok=%v want %v", c.base, ok, c.ok)
			continue
		}
		if ok && (comp.Name != c.name || comp.Version != c.version) {
			t.Errorf("%s: got %s@%s want %s@%s", c.base, comp.Name, comp.Version, c.name, c.version)
		}
	}
}

// TestBinClassifierCatalogerDetectsBinary drives the classifier through the
// real Catalog/TreeFromMap path, the way a binary cataloger encounters an
// interpreter binary inside an image layer: a file named like a known runtime,
// containing an embedded version string, must surface as a component.
func TestBinClassifierCatalogerDetectsBinary(t *testing.T) {
	comps := runCataloger(t, binClassifierCataloger{}, map[string][]byte{
		"usr/local/bin/python3.9": []byte("junkjunk3.9.25 (main, Jan  1 2026)junkjunk"),
	})
	got := byName(comps)
	py, ok := got["python"]
	if !ok {
		t.Fatalf("python not cataloged; got %+v", comps)
	}
	if py.Version != "3.9.25" {
		t.Errorf("python version = %q, want 3.9.25", py.Version)
	}
	if py.Source != "/usr/local/bin/python3.9" {
		t.Errorf("python source = %q, want /usr/local/bin/python3.9", py.Source)
	}
	if py.FoundBy != (binClassifierCataloger{}).Name() {
		t.Errorf("python found_by = %q, want %q", py.FoundBy, (binClassifierCataloger{}).Name())
	}
}

// TestBinClassifierCatalogerNoVersionString covers a file whose name matches
// a known runtime but whose contents carry no recognizable version string:
// it must contribute nothing, and must not panic.
func TestBinClassifierCatalogerNoVersionString(t *testing.T) {
	comps := runCataloger(t, binClassifierCataloger{}, map[string][]byte{
		"usr/local/bin/python3.9": []byte("no version string in here at all"),
	})
	if len(comps) != 0 {
		t.Errorf("expected no components, got %+v", comps)
	}
}

// TestBinClassifierCatalogerNonRuntimeFilename covers a file whose contents
// look exactly like an embedded runtime version string, but whose filename
// does not match any known runtime; the filename gate must suppress it.
func TestBinClassifierCatalogerNonRuntimeFilename(t *testing.T) {
	comps := runCataloger(t, binClassifierCataloger{}, map[string][]byte{
		"usr/share/doc/README": []byte("this mentions python3.9.25 (main, Jan  1 2026) in prose"),
	})
	if len(comps) != 0 {
		t.Errorf("expected no components for non-runtime filename, got %+v", comps)
	}
}

// TestBinClassifierCatalogerDetectsSharedLibrary mirrors
// TestBinClassifierCatalogerDetectsBinary but for the shared-library path:
// the distro's python3.9 launcher is often a stub with no version string, so
// the classifier must also recognize the real CPython build living in
// libpython3.9.so.1.0 and pull its patch version out of the .so's contents.
func TestBinClassifierCatalogerDetectsSharedLibrary(t *testing.T) {
	comps := runCataloger(t, binClassifierCataloger{}, map[string][]byte{
		"usr/local/lib/libpython3.9.so.1.0": []byte("junkjunk\x003.9.25\x00junkjunk"),
	})
	got := byName(comps)
	py, ok := got["python"]
	if !ok {
		t.Fatalf("python not cataloged; got %+v", comps)
	}
	if py.Version != "3.9.25" {
		t.Errorf("python version = %q, want 3.9.25", py.Version)
	}
	if py.Source != "/usr/local/lib/libpython3.9.so.1.0" {
		t.Errorf("python source = %q, want /usr/local/lib/libpython3.9.so.1.0", py.Source)
	}
	if py.FoundBy != (binClassifierCataloger{}).Name() {
		t.Errorf("python found_by = %q, want %q", py.FoundBy, (binClassifierCataloger{}).Name())
	}
}

// TestBinClassifierCatalogerIgnoresUnrelatedSharedLibraries covers two ways a
// .so file can fail to classify: no version digits in the filename at all
// (libpython.so, no major.minor for the soClassifier's nameRe to extract),
// and a shared library for a runtime this package doesn't track (libssl.so).
// Neither should produce a component or panic, even though libssl.so's
// contents look exactly like a version string this package does know how to
// parse (it's just gated by the wrong filename).
func TestBinClassifierCatalogerIgnoresUnrelatedSharedLibraries(t *testing.T) {
	comps := runCataloger(t, binClassifierCataloger{}, map[string][]byte{
		"usr/local/lib/libpython.so":         []byte("totally 3.9.25 legit"),
		"usr/lib/x86_64-linux-gnu/libssl.so": []byte("OpenSSL 3.5.1 8 Jul 2025"),
	})
	if len(comps) != 0 {
		t.Errorf("expected no components, got %+v", comps)
	}
}

// TestBinClassifierCatalogerMaxReadTruncation covers maxBinClassifyRead: the
// cataloger truncates a candidate file's contents to that cap before
// scanning for a version string, so a version string is invisible when it
// sits entirely past the cap, and still found when it sits within it.
func TestBinClassifierCatalogerMaxReadTruncation(t *testing.T) {
	pad := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = 'x'
		}
		return b
	}

	t.Run("past cap is not found", func(t *testing.T) {
		blob := append(pad(maxBinClassifyRead+64), []byte(" 9.9.9 (main)")...)
		comps := runCataloger(t, binClassifierCataloger{}, map[string][]byte{
			"usr/local/bin/python3.9": blob,
		})
		if len(comps) != 0 {
			t.Errorf("expected version string past the cap to be truncated away, got %+v", comps)
		}
	})

	t.Run("within cap is found", func(t *testing.T) {
		blob := append([]byte("9.9.9 (main) "), pad(maxBinClassifyRead-64)...)
		comps := runCataloger(t, binClassifierCataloger{}, map[string][]byte{
			"usr/local/bin/python3.9": blob,
		})
		got := byName(comps)
		py, ok := got["python"]
		if !ok {
			t.Fatalf("expected version string within the cap to be found, got %+v", comps)
		}
		if py.Version != "9.9.9" {
			t.Errorf("python version = %q, want 9.9.9", py.Version)
		}
	})
}

// TestNormalizeDropsRedundantBinaryHit verifies the cataloger-merge dedup: if
// a package-database cataloger (e.g. apk) already produced a component for
// the same runtime, a later binary-classifier hit for that runtime must not
// survive normalize() as a second component — even though real distro
// catalogers never use the exact Name+"@"+Version the binary classifier
// reports (they use the distro's own package name, e.g. "python3" not
// "python", and a revisioned version, e.g. "3.11.6-r0" not "3.11.6").
func TestNormalizeDropsRedundantBinaryHit(t *testing.T) {
	cases := []struct {
		name       string
		osName     string
		osVersion  string
		osPURL     string
		binVersion string
	}{
		{
			name:       "alpine apk revision",
			osName:     "python3",
			osVersion:  "3.11.6-r0",
			osPURL:     "pkg:apk/alpine/python3@3.11.6-r0",
			binVersion: "3.11.6",
		},
		{
			name:       "debian dpkg revision with security suffix",
			osName:     "python3.11",
			osVersion:  "3.11.2-1+deb12u1",
			osPURL:     "pkg:deb/debian/python3.11@3.11.2-1+deb12u1",
			binVersion: "3.11.2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &SBOM{
				Components: []Component{
					{Type: TypeApp, Name: tc.osName, Version: tc.osVersion, FoundBy: "apk", PURL: tc.osPURL},
					{Type: TypeApp, Name: "python", Version: tc.binVersion, FoundBy: (binClassifierCataloger{}).Name(), PURL: "pkg:generic/python@" + tc.binVersion},
				},
			}
			s.normalize()
			if len(s.Components) != 1 {
				t.Fatalf("expected 1 component after dedup, got %d: %+v", len(s.Components), s.Components)
			}
			if s.Components[0].FoundBy != "apk" {
				t.Errorf("expected the package-DB component to survive, got FoundBy=%q", s.Components[0].FoundBy)
			}
		})
	}
}

// TestNormalizeKeepsBinaryHitWhenNoPackageMatch verifies the dedup pass does
// not eat a binary-classifier component when nothing else claims the same
// name@version.
func TestNormalizeKeepsBinaryHitWhenNoPackageMatch(t *testing.T) {
	s := &SBOM{
		Components: []Component{
			{Type: TypeApp, Name: "python", Version: "3.9.25", FoundBy: (binClassifierCataloger{}).Name(), PURL: "pkg:generic/python@3.9.25"},
		},
	}
	s.normalize()
	if len(s.Components) != 1 {
		t.Fatalf("expected the binary component to survive, got %d: %+v", len(s.Components), s.Components)
	}
}

// TestCrossEcosystemKeyNormalization pins down the name/version normalization
// dropRedundantBinaryHits relies on, independent of the full normalize()
// dedup path.
func TestCrossEcosystemKeyNormalization(t *testing.T) {
	nameCases := []struct{ in, want string }{
		{"python3", "python"},
		{"python3.11", "python"},
		{"python", "python"},
		{"openssl", "openssl"},
		{"busybox", "busybox"},
	}
	for _, c := range nameCases {
		if got := normalizeRuntimeName(c.in); got != c.want {
			t.Errorf("normalizeRuntimeName(%q) = %q, want %q", c.in, got, c.want)
		}
	}

	versionCases := []struct{ in, want string }{
		{"3.11.6-r0", "3.11.6"},        // Alpine apk revision
		{"3.11.2-1", "3.11.2"},         // bare Debian revision
		{"3.11.2-1+deb12u1", "3.11.2"}, // Debian security-suffixed revision
		{"1.36.1-r5", "1.36.1"},        // Alpine busybox revision
		{"20.11.1", "20.11.1"},         // no revision suffix at all
		{"1.0.2~exp1-1", "1.0.2"},      // ~ backport marker
	}
	for _, c := range versionCases {
		if got := normalizeRuntimeVersion(c.in); got != c.want {
			t.Errorf("normalizeRuntimeVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSafeClassifyBinaryRecoversPanic proves safeClassifyBinary's
// defer/recover turns a panic during per-file classification into "skip this
// file" rather than crashing the whole cataloger. classifyBinaryFn is
// substituted with a stand-in that panics, since classifyBinary itself (a
// straightforward regexp scan over bytes) has no realistic panic path to
// trigger with crafted input — the seam exists purely to exercise the
// recover path defensively, matching the fail-soft design in generate.go.
func TestSafeClassifyBinaryRecoversPanic(t *testing.T) {
	old := classifyBinaryFn
	classifyBinaryFn = func(base string, blob []byte) (Component, bool) {
		panic("simulated panic while classifying a candidate file")
	}
	t.Cleanup(func() { classifyBinaryFn = old })

	comps := runCataloger(t, binClassifierCataloger{}, map[string][]byte{
		"usr/local/bin/python3.9": []byte("junkjunk3.9.25 (main, Jan  1 2026)junkjunk"),
	})
	if len(comps) != 0 {
		t.Fatalf("expected zero components when classification panics, got %+v", comps)
	}
}
