package license

import "testing"

func TestClassify(t *testing.T) {
	cases := map[string]Class{
		"MIT":                ClassPermissive,
		"Apache-2.0":         ClassPermissive,
		"BSD-3-Clause":       ClassPermissive,
		"ISC":                ClassPermissive,
		"LGPL-2.1-only":      ClassWeakCopyleft,
		"MPL-2.0":            ClassWeakCopyleft,
		"GPL-2.0-only":       ClassStrongCopyleft,
		"GPL-3.0-or-later":   ClassStrongCopyleft,
		"AGPL-3.0-only":      ClassNetworkCopyleft,
		"SomeProprietaryLic": ClassUnknown,
		"":                   ClassUnknown,
	}
	for in, want := range cases {
		if got := classify(in); got != want {
			t.Errorf("classify(%q) = %s, want %s", in, got, want)
		}
	}
}

func lics(ids ...string) []LicenseID {
	out := make([]LicenseID, len(ids))
	for i, id := range ids {
		out[i] = LicenseID{ID: id}
	}
	return out
}

func TestEmptyPolicyDeniesNothing(t *testing.T) {
	p := &Policy{}
	if !p.Empty() {
		t.Fatal("zero Policy should be Empty()")
	}
	if v := p.Evaluate(lics("GPL-3.0-only")); v.Denied {
		t.Errorf("empty policy denied %+v", v)
	}
}

func TestDenyList(t *testing.T) {
	p := &Policy{Deny: []string{"GPL-3.0-only"}}
	v := p.Evaluate(lics("MIT", "GPL-3.0-only"))
	if !v.Denied || v.Reason != ReasonDenied || v.License != "GPL-3.0-only" {
		t.Fatalf("deny-list verdict = %+v", v)
	}
	if v := p.Evaluate(lics("MIT")); v.Denied {
		t.Errorf("MIT should pass a GPL-only deny list, got %+v", v)
	}
}

func TestDenyListCaseInsensitive(t *testing.T) {
	p := &Policy{Deny: []string{"gpl-3.0-only"}}
	if v := p.Evaluate(lics("GPL-3.0-ONLY")); !v.Denied {
		t.Errorf("deny match should be case-insensitive, got %+v", v)
	}
}

func TestAllowList(t *testing.T) {
	p := &Policy{Allow: []string{"MIT", "Apache-2.0"}}
	if v := p.Evaluate(lics("MIT")); v.Denied {
		t.Errorf("MIT is allowlisted but was denied: %+v", v)
	}
	v := p.Evaluate(lics("BSD-3-Clause"))
	if !v.Denied || v.Reason != ReasonNotAllowed {
		t.Fatalf("non-allowlisted license verdict = %+v, want not-in-allowlist", v)
	}
}

func TestDenyClasses(t *testing.T) {
	p := &Policy{DenyClasses: []Class{ClassStrongCopyleft, ClassNetworkCopyleft}}
	if v := p.Evaluate(lics("AGPL-3.0-only")); !v.Denied || v.Reason != ReasonDenied {
		t.Errorf("AGPL should be denied by network-copyleft class, got %+v", v)
	}
	if v := p.Evaluate(lics("LGPL-2.1-only")); v.Denied {
		t.Errorf("LGPL (weak) should pass a strong/network class deny, got %+v", v)
	}
}

func TestFlagUnknown(t *testing.T) {
	p := &Policy{FlagUnknown: true}
	if v := p.Evaluate(lics("WeirdCustomLicense")); !v.Denied || v.Reason != ReasonUnknown {
		t.Errorf("unknown license should be flagged, got %+v", v)
	}
	if v := p.Evaluate(lics("MIT")); v.Denied {
		t.Errorf("MIT is known-permissive, should not be flagged, got %+v", v)
	}
}

func TestFlagUnlicensed(t *testing.T) {
	p := &Policy{FlagUnlicensed: true}
	if v := p.Evaluate(nil); !v.Denied || v.Reason != ReasonUnlicensed {
		t.Errorf("no-license component should be flagged, got %+v", v)
	}
	// A component WITH a license does not trip the unlicensed flag.
	if v := p.Evaluate(lics("MIT")); v.Denied {
		t.Errorf("licensed component tripped unlicensed flag: %+v", v)
	}
}

func TestEvaluateDeterministicCause(t *testing.T) {
	// Two denied licenses; the reported cause must be stable regardless of input
	// order (sorted), so goldens don't flap.
	p := &Policy{Deny: []string{"GPL-3.0-only", "AGPL-3.0-only"}}
	v1 := p.Evaluate(lics("GPL-3.0-only", "AGPL-3.0-only"))
	v2 := p.Evaluate(lics("AGPL-3.0-only", "GPL-3.0-only"))
	if v1.License != v2.License {
		t.Errorf("cause not order-stable: %q vs %q", v1.License, v2.License)
	}
	if v1.License != "AGPL-3.0-only" {
		t.Errorf("expected sorted-first cause AGPL-3.0-only, got %q", v1.License)
	}
}

func TestNameFallback(t *testing.T) {
	// When only a free-text Name is present, it is evaluated too.
	p := &Policy{Deny: []string{"Commercial"}}
	if v := p.Evaluate([]LicenseID{{Name: "Commercial"}}); !v.Denied {
		t.Errorf("free-text license name should be evaluated, got %+v", v)
	}
}
