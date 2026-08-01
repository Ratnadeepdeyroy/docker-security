package vulndb

import "testing"

// cmpCase is one comparison expectation: Compare(a,b) should return want.
type cmpCase struct {
	a, b string
	want int
}

// runCmpTable exercises a comparator table and, for every case, also asserts
// antisymmetry (Compare(b,a) == -Compare(a,b)) — the property a broken
// comparator most often violates and the one that silently corrupts range
// matching.
func runCmpTable(t *testing.T, sch VersionScheme, cases []cmpCase) {
	t.Helper()
	for _, c := range cases {
		got := Compare(sch, c.a, c.b)
		if got != c.want {
			t.Errorf("[%s] Compare(%q,%q) = %d, want %d", sch, c.a, c.b, got, c.want)
		}
		if rev := Compare(sch, c.b, c.a); rev != -c.want {
			t.Errorf("[%s] antisymmetry broken: Compare(%q,%q)=%d but Compare(%q,%q)=%d",
				sch, c.a, c.b, c.want, c.b, c.a, rev)
		}
	}
}

func TestCompareSemver(t *testing.T) {
	runCmpTable(t, SchemeSemver, []cmpCase{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.2.0", "1.10.0", -1}, // numeric, not lexical
		{"2.0.0", "1.9.9", 1},
		{"1.0.0-alpha", "1.0.0", -1}, // pre-release < release
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"1.0.0-alpha.1", "1.0.0-alpha.beta", -1},
		{"1.0.0-alpha.beta", "1.0.0-beta", -1},
		{"1.0.0-beta", "1.0.0-beta.2", -1},
		{"1.0.0-beta.2", "1.0.0-beta.11", -1}, // numeric identifiers compare numerically
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0+build.99", "1.0.0", 0}, // build metadata ignored
		{"v1.2.3", "1.2.3", 0},
		{"1.2", "1.2.0", 0},
	})
}

func TestCompareDeb(t *testing.T) {
	runCmpTable(t, SchemeDeb, []cmpCase{
		{"1.0", "1.0", 0},
		{"1.0-1", "1.0-2", -1},
		{"1.0.0", "1.0", 1},
		{"2:1.0", "1:9.0", 1},  // epoch dominates
		{"1:1.0", "1.0", 1},    // epoch 1 > implicit 0
		{"1.0~rc1", "1.0", -1}, // tilde sorts before release
		{"1.0~~", "1.0~", -1},  // more tildes = smaller
		{"1.0-1ubuntu1", "1.0-1", 1},
		{"5.1-2+deb11u1", "5.1-2", 1},
		{"1.3.1-r0", "1.3.1-r1", -1},
	})
}

func TestCompareRPM(t *testing.T) {
	runCmpTable(t, SchemeRPM, []cmpCase{
		{"1.0", "1.0", 0},
		{"1.0-1", "1.0-2", -1},
		{"1:1.0", "2.0", 1}, // epoch dominates
		{"1.0", "1.0.1", -1},
		{"1.0.1", "1.0.10", -1},
		{"1.0~beta", "1.0", -1},    // tilde
		{"1.0^20240101", "1.0", 1}, // caret sorts after
		{"1.0a", "1.0", 1},         // trailing alpha segment
		{"1.0-1.el8", "1.0-1.el9", -1},
		{"2.0.1", "2.0.1", 0},
	})
}

func TestCompareAPK(t *testing.T) {
	runCmpTable(t, SchemeAPK, []cmpCase{
		{"1.2.4-r2", "1.2.4-r3", -1},
		{"1.2.3", "1.2.10", -1},
		{"1.0", "1.0-r0", 0},
		{"1.2.4-r2", "1.2.4", 1},  // build revision > none
		{"1.0_alpha1", "1.0", -1}, // pre-release suffix
		{"1.0_alpha", "1.0_beta", -1},
		{"1.0_rc1", "1.0_rc2", -1},
		{"1.0", "1.0_p1", -1}, // post-release suffix
		{"1.36.1-r5", "1.36.1-r5", 0},
	})
}

func TestComparePEP440(t *testing.T) {
	runCmpTable(t, SchemePEP440, []cmpCase{
		{"1.0", "1.0.0", 0},
		{"1.0", "1.0.1", -1},
		{"2.31.0", "2.30.1", 1},
		{"1.0rc1", "1.0", -1},
		{"1.0a1", "1.0b1", -1},
		{"1.0b1", "1.0rc1", -1},
		{"1.0.dev1", "1.0a1", -1}, // dev precedes pre-release
		{"1.0", "1.0.post1", -1},
		{"1.0.post1", "1.0.post2", -1},
		{"1!1.0", "2.0", 1},         // epoch dominates
		{"1.0a1.dev1", "1.0a1", -1}, // dev of a pre-release
	})
}

func TestCompareGo(t *testing.T) {
	runCmpTable(t, SchemeGo, []cmpCase{
		{"v1.2.3", "v1.2.3", 0},
		{"v1.2.3", "v1.2.4", -1},
		{"v1.10.0", "v1.9.0", 1},
		{"v1.2.3-rc1", "v1.2.3", -1},
		{"v1.2.3+incompatible", "v1.2.3", 0},
		// Pseudo-versions order by embedded commit timestamp.
		{"v0.0.0-20210101000000-abcdef012345", "v0.0.0-20220101000000-abcdef012345", -1},
	})
}

func TestCompareMaven(t *testing.T) {
	runCmpTable(t, SchemeMaven, []cmpCase{
		{"1.0", "1", 0},
		{"1.0", "1.0.0", 0},
		{"1.2", "1.10", -1},
		{"1.0-alpha", "1.0", -1},
		{"1.0-alpha", "1.0-beta", -1},
		{"1.0-beta", "1.0-milestone", -1},
		{"1.0-milestone", "1.0-rc", -1},
		{"1.0-rc", "1.0-snapshot", -1},
		{"1.0-snapshot", "1.0", -1},
		{"1.0", "1.0-sp", -1},
		{"1.0-rc1", "1.0-rc2", -1},
		{"1.0-foo", "1.0", 1}, // unknown qualifier sorts after release
	})
}

func TestCompareGeneric(t *testing.T) {
	runCmpTable(t, SchemeGeneric, []cmpCase{
		{"1.0", "1.0", 0},
		{"1.0", "1.1", -1},
		{"1.2", "1.10", -1},
		{"1.0a", "1.0b", -1},
		{"1.0", "1.0.1", -1},
	})
}

// TestCompareHostileInput ensures pathological version strings never panic and
// always yield a total order (the tool must survive adversarial SBOM data).
func TestCompareHostileInput(t *testing.T) {
	nasty := []string{"", "~", "^", ":", "-", "...", "1:2:3", "999999999999999999999999999", "\x00\x01", "a.b.c"}
	for _, sch := range []VersionScheme{SchemeSemver, SchemeDeb, SchemeRPM, SchemeAPK, SchemePEP440, SchemeGo, SchemeMaven, SchemeGeneric} {
		for _, a := range nasty {
			for _, b := range nasty {
				got := Compare(sch, a, b)
				if got < -1 || got > 1 {
					t.Errorf("[%s] Compare(%q,%q) out of range: %d", sch, a, b, got)
				}
				if rev := Compare(sch, b, a); rev != -got {
					t.Errorf("[%s] antisymmetry broken on hostile input %q/%q: %d vs %d", sch, a, b, got, rev)
				}
			}
		}
	}
}
