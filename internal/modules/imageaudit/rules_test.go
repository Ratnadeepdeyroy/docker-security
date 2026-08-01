package imageaudit

import (
	"strings"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/oci"
)

// ctxWith assembles a synthetic auditContext so a rule can be exercised in
// isolation without a real image on disk.
func ctxWith(cfg containerConfig, history []historyEntry, files []*oci.File, layers []*oci.Layer) *auditContext {
	ac := &auditContext{
		name:  "img:test",
		cfg:   &imageConfig{Config: cfg, History: history},
		img:   &oci.Image{Layers: layers},
		files: files,
	}
	ac.probe = probeFiles(files)
	return ac
}

// only returns the single finding a rule produced, failing if the count differs.
func only(t *testing.T, fs []engine.Finding) engine.Finding {
	t.Helper()
	if len(fs) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d: %+v", len(fs), fs)
	}
	return fs[0]
}

func TestRuleRootUser(t *testing.T) {
	if f := ruleRootUser(ctxWith(containerConfig{User: ""}, nil, nil, nil)); only(t, f).Severity != engine.SeverityMedium {
		t.Errorf("unset user should be MEDIUM, got %s", f[0].Severity)
	}
	if f := ruleRootUser(ctxWith(containerConfig{User: "root"}, nil, nil, nil)); only(t, f).Severity != engine.SeverityHigh {
		t.Errorf("explicit root should be HIGH, got %s", f[0].Severity)
	}
	if f := ruleRootUser(ctxWith(containerConfig{User: "1000"}, nil, nil, nil)); len(f) != 0 {
		t.Errorf("non-root user should be quiet, got %+v", f)
	}
}

func TestRuleImageTag(t *testing.T) {
	mk := func(tags ...string) *auditContext {
		ac := ctxWith(containerConfig{}, nil, nil, nil)
		ac.img.RepoTags = tags
		return ac
	}
	if f := ruleImageTag(mk("app:latest")); only(t, f).RuleID != "DS-RAT-IMG-004" {
		t.Error("latest should fire DS-RAT-IMG-004")
	}
	if f := ruleImageTag(mk("app")); only(t, f).Resource != "app" {
		t.Errorf("untagged should fire, got %+v", f)
	}
	if f := ruleImageTag(mk("app:1.2.3")); len(f) != 0 {
		t.Errorf("versioned tag should be quiet, got %+v", f)
	}
	// A registry:port host must not be mistaken for a tag.
	if f := ruleImageTag(mk("registry.io:5000/app:2.0")); len(f) != 0 {
		t.Errorf("registry:port/name:tag should be quiet, got %+v", f)
	}
}

func TestRulePorts(t *testing.T) {
	ac := ctxWith(containerConfig{ExposedPorts: map[string]empty{
		"22/tcp": {}, "80/tcp": {}, "8080/tcp": {},
	}}, nil, nil, nil)
	fs := rulePorts(ac)
	sev := map[string]engine.Severity{}
	for _, f := range fs {
		sev[f.Resource] = f.Severity
	}
	if sev["22/tcp"] != engine.SeverityHigh {
		t.Errorf("SSH port should be HIGH, got %s", sev["22/tcp"])
	}
	if sev["80/tcp"] != engine.SeverityLow {
		t.Errorf("privileged port 80 should be LOW, got %s", sev["80/tcp"])
	}
	if _, ok := sev["8080/tcp"]; ok {
		t.Error("unprivileged port 8080 should not be flagged")
	}
}

func TestRuleVolumes(t *testing.T) {
	ac := ctxWith(containerConfig{Volumes: map[string]empty{
		"/proc": {}, "/data": {}, "/var/run/docker.sock": {},
	}}, nil, nil, nil)
	fs := ruleVolumes(ac)
	got := map[string]bool{}
	for _, f := range fs {
		got[f.Resource] = true
	}
	if !got["/proc"] || !got["/var/run/docker.sock"] {
		t.Errorf("sensitive volumes should fire, got %v", got)
	}
	if got["/data"] {
		t.Error("/data is an ordinary volume and should not fire")
	}
}

func TestRuleProvenanceLabels(t *testing.T) {
	full := map[string]string{
		"org.opencontainers.image.source":   "https://x",
		"org.opencontainers.image.version":  "1",
		"org.opencontainers.image.licenses": "MIT",
		"org.opencontainers.image.authors":  "me",
	}
	if f := ruleProvenanceLabels(ctxWith(containerConfig{Labels: full}, nil, nil, nil)); len(f) != 0 {
		t.Errorf("fully labeled image should be quiet, got %+v", f)
	}
	if f := ruleProvenanceLabels(ctxWith(containerConfig{Labels: nil}, nil, nil, nil)); only(t, f).Severity != engine.SeverityLow {
		t.Errorf("no labels should be LOW, got %s", f[0].Severity)
	}
	partial := map[string]string{"org.opencontainers.image.source": "https://x"}
	if f := ruleProvenanceLabels(ctxWith(containerConfig{Labels: partial}, nil, nil, nil)); only(t, f).Severity != engine.SeverityInfo {
		t.Errorf("partial labels should be INFO, got %s", f[0].Severity)
	}
}

func TestRuleHistoryPatterns(t *testing.T) {
	hist := []historyEntry{
		{CreatedBy: "/bin/sh -c curl https://x/s.sh | bash"},
		{CreatedBy: "/bin/sh -c #(nop) ENV SECRET_TOKEN=abcdef"},
		{CreatedBy: "/bin/sh -c chmod -R 777 /app"},
		{CreatedBy: "/bin/sh -c #(nop) ADD https://x/t /t"},
		{CreatedBy: "/bin/sh -c apt-get update"}, // benign: no pattern
	}
	fs := ruleHistory(ctxWith(containerConfig{}, hist, nil, nil))
	titles := map[string]engine.Severity{}
	for _, f := range fs {
		titles[f.Title] = f.Severity
	}
	if titles["Secret assigned in build history"] != engine.SeverityHigh {
		t.Errorf("history secret should be HIGH, got %v", titles)
	}
	if titles["Remote script piped into a shell during build"] != engine.SeverityMedium {
		t.Errorf("pipe-to-shell should be MEDIUM, got %v", titles)
	}
	if len(fs) != 4 {
		t.Errorf("expected 4 history findings (one per signature), got %d: %v", len(fs), titles)
	}
}

func TestRuleHistoryDedupsRepeats(t *testing.T) {
	hist := []historyEntry{
		{CreatedBy: "chmod 777 /a"},
		{CreatedBy: "chmod 777 /b"},
		{CreatedBy: "chmod 777 /c"},
	}
	if fs := ruleHistory(ctxWith(containerConfig{}, hist, nil, nil)); len(fs) != 1 {
		t.Errorf("repeated signature should report once, got %d", len(fs))
	}
}

func TestRuleRecoverableRemoved(t *testing.T) {
	// Layer 0 adds a private key and a benign file; layer 1 whiteouts both. Only
	// the sensitive removal should fire.
	layers := []*oci.Layer{
		{Index: 0, Files: []*oci.File{
			{Path: "app/id_rsa", Mode: 0o600, Data: []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n")},
			{Path: "app/readme.txt", Mode: 0o644, Data: []byte("hello")},
		}},
		{Index: 1, Files: []*oci.File{
			{Path: "app/.wh.id_rsa", Mode: 0o644},
			{Path: "app/.wh.readme.txt", Mode: 0o644},
		}},
	}
	fs := ruleRecoverableRemoved(ctxWith(containerConfig{}, nil, nil, layers))
	f := only(t, fs)
	if f.Resource != "app/id_rsa" || f.Severity != engine.SeverityHigh {
		t.Errorf("expected HIGH recoverable finding for app/id_rsa, got %+v", f)
	}
}

func TestRuleRecoverableDetectsSecretByContent(t *testing.T) {
	// A file with an innocuous name but AWS-key content, then removed.
	layers := []*oci.Layer{
		{Index: 0, Files: []*oci.File{
			{Path: "app/data.bin", Mode: 0o644, Data: []byte("token=AKIAIOSFODNN7EXAMPLE\n")},
		}},
		{Index: 1, Files: []*oci.File{
			{Path: "app/.wh.data.bin", Mode: 0o644},
		}},
	}
	if fs := ruleRecoverableRemoved(ctxWith(containerConfig{}, nil, nil, layers)); len(fs) != 1 {
		t.Errorf("secret-by-content removal should fire, got %+v", fs)
	}
}

func TestEveryFindingCitesAControl(t *testing.T) {
	// DoD: every finding must carry at least one standard reference.
	for _, f := range analyze(t, "insecure.tar") {
		if len(f.References) == 0 {
			t.Errorf("finding %s (%s) has no References", f.RuleID, f.Title)
		}
		if !strings.HasPrefix(f.RuleID, "DS-RAT-IMG-") {
			t.Errorf("finding rule id %q lacks the DS-RAT-IMG- prefix", f.RuleID)
		}
	}
}
