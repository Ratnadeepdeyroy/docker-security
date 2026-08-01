package registry

import "testing"

func TestParseReference(t *testing.T) {
	cases := []struct {
		in       string
		registry string
		repo     string
		tag      string
		digest   string
	}{
		{"alpine", DefaultRegistry, "library/alpine", "latest", ""},
		{"alpine:3.19", DefaultRegistry, "library/alpine", "3.19", ""},
		{"user/app:1.0", DefaultRegistry, "user/app", "1.0", ""},
		{"ghcr.io/org/app:tag", "ghcr.io", "org/app", "tag", ""},
		{"registry:5000/team/app:1.2", "registry:5000", "team/app", "1.2", ""},
		{"localhost:5000/app", "localhost:5000", "app", "latest", ""},
		{
			"ghcr.io/org/app@sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
			"ghcr.io", "org/app", "", "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
		},
		{
			"app:1.0@sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
			DefaultRegistry, "library/app", "1.0", "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
		},
	}
	for _, c := range cases {
		got, err := ParseReference(c.in)
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.in, err)
			continue
		}
		if got.Registry != c.registry || got.Repository != c.repo || got.Tag != c.tag || got.Digest != c.digest {
			t.Errorf("%s:\n got %+v\nwant reg=%s repo=%s tag=%s digest=%s",
				c.in, got, c.registry, c.repo, c.tag, c.digest)
		}
	}
}

func TestParseReferenceRejectsBad(t *testing.T) {
	bad := []string{
		"",
		"app@sha256:short",
		"app@notadigest",
	}
	for _, in := range bad {
		if _, err := ParseReference(in); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

func TestRefForPullPrefersDigest(t *testing.T) {
	r := Reference{Tag: "latest", Digest: "sha256:" + strings64('a')}
	if r.RefForPull() != r.Digest {
		t.Errorf("RefForPull should prefer digest, got %q", r.RefForPull())
	}
	r2 := Reference{Tag: "latest"}
	if r2.RefForPull() != "latest" {
		t.Errorf("RefForPull should fall back to tag, got %q", r2.RefForPull())
	}
}

func strings64(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}
