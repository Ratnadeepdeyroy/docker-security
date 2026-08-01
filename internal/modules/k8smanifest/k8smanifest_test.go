package k8smanifest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

const insecurePod = `
apiVersion: v1
kind: Pod
metadata:
  name: bad
  namespace: prod
spec:
  hostNetwork: true
  containers:
  - name: app
    image: nginx:1.25
    securityContext:
      privileged: true
      runAsNonRoot: false
`

const securePod = `
apiVersion: v1
kind: Pod
metadata:
  name: good
  namespace: prod
spec:
  containers:
  - name: app
    image: nginx@sha256:abc
    securityContext:
      privileged: false
      runAsNonRoot: true
      readOnlyRootFilesystem: true
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
`

func analyze(t *testing.T, content string) []engine.Finding {
	t.Helper()
	m := New()
	findings, err := m.Analyze(context.Background(), &engine.Target{
		Type:     engine.TargetFilesystem,
		Location: "manifest.yaml",
		Content:  []byte(content),
	})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return findings
}

func TestSupports(t *testing.T) {
	m := New()
	if !m.Supports(engine.TargetFilesystem) {
		t.Error("k8smanifest should support filesystem targets")
	}
	if m.Supports(engine.TargetImage) || m.Supports(engine.TargetDockerfile) {
		t.Error("k8smanifest should only support filesystem targets")
	}
}

func TestInsecurePodFlagged(t *testing.T) {
	findings := analyze(t, insecurePod)
	if len(findings) == 0 {
		t.Fatal("insecure pod produced no findings")
	}
	// Rules must be re-tagged into the DS-RAT-K8S namespace, with the harden control
	// preserved in metadata.
	var privileged, hostNet bool
	for _, f := range findings {
		if !strings.HasPrefix(f.RuleID, "DS-RAT-K8S-") {
			t.Errorf("finding %s not in DS-RAT-K8S namespace", f.RuleID)
		}
		if f.Metadata["harden_control"] == "DS-RAT-BOX-001" {
			privileged = true
		}
		if f.Metadata["harden_control"] == "DS-RAT-BOX-009" {
			hostNet = true
		}
		if f.Metadata["source_file"] != "manifest.yaml" {
			t.Errorf("source_file not recorded: %+v", f.Metadata)
		}
	}
	if !privileged {
		t.Error("privileged container not flagged")
	}
	if !hostNet {
		t.Error("hostNetwork not flagged")
	}
}

func TestSecurePodClean(t *testing.T) {
	findings := analyze(t, securePod)
	// A well-hardened pod should produce no FAIL-level (high/critical) findings.
	for _, f := range findings {
		if f.Severity >= engine.SeverityHigh {
			t.Errorf("hardened pod produced a high/critical finding: %s %s", f.RuleID, f.Title)
		}
	}
}

func TestDeploymentTemplateScanned(t *testing.T) {
	// A Deployment wraps the pod under spec.template; harden.Parse unwraps it.
	dep := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  template:
    spec:
      containers:
      - name: app
        image: nginx
        securityContext:
          privileged: true
`
	findings := analyze(t, dep)
	found := false
	for _, f := range findings {
		if f.Metadata["harden_control"] == "DS-RAT-BOX-001" {
			found = true
		}
	}
	if !found {
		t.Errorf("privileged container in a Deployment template not flagged; got %+v", findings)
	}
}

func TestNonWorkloadManifestIgnored(t *testing.T) {
	svc := `
apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  ports:
  - port: 80
`
	findings := analyze(t, svc)
	for _, f := range findings {
		if f.Severity >= engine.SeverityLow {
			t.Errorf("a Service should not produce workload findings, got %s", f.RuleID)
		}
	}
}

func TestDirectoryOfManifests(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.yaml"), []byte(insecurePod), 0o644); err != nil {
		t.Fatal(err)
	}
	// A non-YAML file must be ignored.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# not yaml"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := New()
	findings, err := m.Analyze(context.Background(), &engine.Target{Type: engine.TargetFilesystem, Location: dir})
	if err != nil {
		t.Fatalf("Analyze dir: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("directory scan found nothing")
	}
	for _, f := range findings {
		if !strings.HasSuffix(f.Metadata["source_file"], "a.yaml") {
			t.Errorf("finding sourced from unexpected file: %q", f.Metadata["source_file"])
		}
	}
}

func TestMultiDocFile(t *testing.T) {
	multi := securePod + "\n---\n" + insecurePod
	findings := analyze(t, multi)
	// The insecure doc must still be flagged even though a clean doc precedes it.
	found := false
	for _, f := range findings {
		if f.Metadata["harden_control"] == "DS-RAT-BOX-001" {
			found = true
		}
	}
	if !found {
		t.Error("insecure doc in a multi-doc file not flagged")
	}
}
