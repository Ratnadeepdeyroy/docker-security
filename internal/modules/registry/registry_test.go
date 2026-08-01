package registry

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// ids returns the sorted set of rule IDs a scan produced, for order-independent
// assertions.
func ids(fs []engine.Finding) []string {
	seen := map[string]bool{}
	for _, f := range fs {
		seen[f.RuleID] = true
	}
	var out []string
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func run(t *testing.T, tgt *engine.Target) []engine.Finding {
	t.Helper()
	fs, err := New().Analyze(context.Background(), tgt)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return fs
}

func df(content string, md map[string]string) *engine.Target {
	return &engine.Target{Type: engine.TargetDockerfile, Content: []byte(content), Location: "Dockerfile", Metadata: md}
}

func wantIDs(t *testing.T, fs []engine.Finding, want ...string) {
	t.Helper()
	got := ids(fs)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("rule IDs = %v, want %v", got, want)
	}
}

func TestModuleShape(t *testing.T) {
	m := New()
	if m.Name() != "registry" {
		t.Errorf("Name = %q", m.Name())
	}
	if got := m.Domains(); len(got) != 1 || got[0] != "13" {
		t.Errorf("Domains = %v, want [13]", got)
	}
	for _, tt := range []engine.TargetType{engine.TargetDockerfile, engine.TargetImage, engine.TargetRegistry} {
		if !m.Supports(tt) {
			t.Errorf("Supports(%s) = false", tt)
		}
	}
	if m.Supports(engine.TargetFilesystem) {
		t.Errorf("Supports(filesystem) = true, want false")
	}
}

func TestAdvisoryModePublicMutable(t *testing.T) {
	// No allowlist: a plain public + tag pull should flag mutable-tag + public.
	fs := run(t, df("FROM alpine:3.19\n", nil))
	wantIDs(t, fs, ruleMutableTag, rulePublicSource)
}

func TestDigestPinnedNoMutableFinding(t *testing.T) {
	dg := "FROM alpine@sha256:" + strings.Repeat("a", 64) + "\n"
	fs := run(t, df(dg, nil))
	// digest-pinned => no DS-RAT-REG-001; still a public-source advisory.
	wantIDs(t, fs, rulePublicSource)
}

func TestAllowlistModeUntrusted(t *testing.T) {
	md := map[string]string{"registry.allow": "ghcr.io,registry.corp.local"}
	fs := run(t, df("FROM docker.io/library/alpine:3.19\n", md))
	wantIDs(t, fs, ruleMutableTag, ruleUntrusted)
}

func TestAllowlistModeTrustedDigestClean(t *testing.T) {
	md := map[string]string{"registry.allow": "ghcr.io"}
	dg := "FROM ghcr.io/org/app@sha256:" + strings.Repeat("b", 64) + "\n"
	fs := run(t, df(dg, md))
	if len(fs) != 0 {
		t.Fatalf("expected no findings for allowlisted digest-pinned ref, got %v", ids(fs))
	}
}

func TestInsecureScheme(t *testing.T) {
	fs := run(t, df("FROM http://myreg.local/app:1\n", nil))
	if !hasID(fs, ruleInsecure) {
		t.Fatalf("expected %s, got %v", ruleInsecure, ids(fs))
	}
}

func TestInsecureListedHost(t *testing.T) {
	md := map[string]string{"registry.insecure": "myreg.local"}
	fs := run(t, df("FROM myreg.local/app:1\n", md))
	if !hasID(fs, ruleInsecure) {
		t.Fatalf("expected %s for listed insecure host, got %v", ruleInsecure, ids(fs))
	}
}

func TestTyposquatSubstitution(t *testing.T) {
	// "ngonx" is one substitution from "nginx".
	fs := run(t, df("FROM ngonx:1.25\n", nil))
	if !hasID(fs, ruleTyposquat) {
		t.Fatalf("expected %s for near-miss name, got %v", ruleTyposquat, ids(fs))
	}
}

func TestPopularNameNonOfficialNamespace(t *testing.T) {
	fs := run(t, df("FROM ghcr.io/evil/nginx:1\n", nil))
	if !hasID(fs, ruleTyposquat) {
		t.Fatalf("expected %s for popular name in foreign namespace, got %v", ruleTyposquat, ids(fs))
	}
}

func TestOfficialPopularImageNotFlaggedTyposquat(t *testing.T) {
	fs := run(t, df("FROM nginx:1.25\n", nil))
	if hasID(fs, ruleTyposquat) {
		t.Fatalf("official nginx should not be a typosquat: %v", ids(fs))
	}
}

func TestSkipScratchAndStageRefs(t *testing.T) {
	content := "FROM golang:1.22 AS build\nRUN go build\nFROM scratch\nCOPY --from=build /app /app\n"
	fs := run(t, df(content, nil))
	// Only golang:1.22 is a real base; scratch is skipped, no stage ref here.
	for _, f := range fs {
		if !strings.Contains(f.Resource, "golang") {
			t.Errorf("unexpected finding on %q: %s", f.Resource, f.RuleID)
		}
	}
	if !hasID(fs, ruleMutableTag) {
		t.Fatalf("expected golang:1.22 flagged mutable, got %v", ids(fs))
	}
}

func TestStageAliasReferenceSkipped(t *testing.T) {
	content := "FROM alpine:3.19 AS base\nFROM base\nRUN true\n"
	fs := run(t, df(content, nil))
	// `FROM base` references the earlier stage; only alpine should be audited.
	for _, f := range fs {
		if strings.Contains(f.Resource, "base") && !strings.Contains(f.Resource, "alpine") {
			t.Errorf("stage ref should be skipped, got finding on %q", f.Resource)
		}
	}
}

func TestImageTargetUsesDockerRef(t *testing.T) {
	tgt := &engine.Target{
		Type:     engine.TargetImage,
		Location: "/tmp/alpine.tar",
		Metadata: map[string]string{"docker.ref": "alpine:3.19"},
	}
	fs := run(t, tgt)
	wantIDs(t, fs, ruleMutableTag, rulePublicSource)
}

func TestImageTargetLocalTarIgnored(t *testing.T) {
	tgt := &engine.Target{Type: engine.TargetImage, Location: "/tmp/alpine.tar"}
	fs := run(t, tgt)
	if len(fs) != 0 {
		t.Fatalf("local tar path should yield no refs, got %v", ids(fs))
	}
}

func TestRegistryTarget(t *testing.T) {
	tgt := &engine.Target{Type: engine.TargetRegistry, Location: "quay.io/org/app:1.0"}
	fs := run(t, tgt)
	wantIDs(t, fs, ruleMutableTag, rulePublicSource)
}

func TestEditDistance1(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"nginx", "nginx", false}, // identical
		{"ngonx", "nginx", true},  // substitution
		{"ngin", "nginx", true},   // deletion
		{"nginxx", "nginx", true}, // insertion
		{"redis", "nginx", false}, // far
		{"postgres", "postgre", true},
		{"aa", "bb", false}, // two subs
	}
	for _, c := range cases {
		if got := editDistance1(c.a, c.b); got != c.want {
			t.Errorf("editDistance1(%q,%q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func hasID(fs []engine.Finding, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}
