// Package k8smanifest is the offline Kubernetes-manifest linter
// (CAPABILITY_SPEC domains 8/10). The kubebench module audits a live cluster and
// the admission module gates at admit-time; neither lints a directory of Helm-
// rendered / kustomize / plain YAML workloads before they reach a cluster. This
// module fills that gap: it reads YAML manifests, converts each document to JSON
// with the dependency-free reader in internal/k8syaml, and reuses the harden
// Workload posture checks (runAsNonRoot, drop-caps, readOnlyRootFs, no
// hostPath/hostNetwork, privileged, seccomp, …) — so the same rules that guard a
// running pod also gate a manifest in CI.
package k8smanifest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	hardenlib "github.com/Ratnadeepdeyroy/docker-security/internal/harden"
	"github.com/Ratnadeepdeyroy/docker-security/internal/k8syaml"
)

const moduleName = "k8smanifest"

// Module implements the offline manifest scan.
type Module struct{}

// New returns a k8smanifest module.
func New() *Module { return &Module{} }

// Register adds the module to a registry.
func Register(r *engine.Registry) { r.Register(New()) }

func (m *Module) Name() string { return moduleName }
func (m *Module) Description() string {
	return "Offline Kubernetes manifest linter: workload posture over YAML files/dirs (Helm/kustomize/plain) (domains 8,10)"
}
func (m *Module) Domains() []string { return []string{"8", "10"} }

// Supports filesystem targets. A single .yaml file or a directory of them is a
// filesystem target; the module ignores non-YAML inputs so it can share a target
// type with other filesystem modules without stealing their work.
func (m *Module) Supports(t engine.TargetType) bool {
	return t == engine.TargetFilesystem
}

// Analyze reads the manifest(s), verifies each workload's hardening posture, and
// returns DS-RAT-K8S-* findings. Inlined Content (a single manifest passed directly)
// is scanned as one file; otherwise Location is read as a file or walked as a
// directory tree.
func (m *Module) Analyze(_ context.Context, t *engine.Target) ([]engine.Finding, error) {
	sources, err := collectSources(t)
	if err != nil {
		return nil, err
	}

	var findings []engine.Finding
	for _, src := range sources {
		docs := k8syaml.SplitDocuments(string(src.data))
		for i, doc := range docs {
			jsonDoc, err := k8syaml.ToJSON(doc)
			if err != nil {
				findings = append(findings, parseWarning(src.name, i, err))
				continue
			}
			jsonDoc = unwrapTemplate(jsonDoc)
			workloads, err := hardenlib.Parse(jsonDoc)
			if err != nil || len(workloads) == 0 {
				continue // not a workload manifest (Service, ConfigMap, …) or unparseable kind
			}
			for wi := range workloads {
				w := &workloads[wi]
				rep := hardenlib.Verify(w)
				for _, f := range rep.Findings(moduleName) {
					findings = append(findings, retag(f, src.name))
				}
			}
		}
	}
	sortFindings(findings)
	return findings, nil
}

type source struct {
	name string
	data []byte
}

// collectSources gathers manifest bytes from inline Content, a single file, or a
// directory walked for .yaml/.yml files.
func collectSources(t *engine.Target) ([]source, error) {
	if len(t.Content) > 0 {
		return []source{{name: firstNonEmpty(t.Location, "<inline>"), data: t.Content}}, nil
	}
	if t.Location == "" {
		return nil, fmt.Errorf("k8smanifest: no content or location")
	}
	info, err := os.Stat(t.Location)
	if err != nil {
		return nil, fmt.Errorf("k8smanifest: %w", err)
	}
	if !info.IsDir() {
		data, err := os.ReadFile(t.Location)
		if err != nil {
			return nil, fmt.Errorf("k8smanifest: %w", err)
		}
		return []source{{name: t.Location, data: data}}, nil
	}

	var out []source
	err = filepath.WalkDir(t.Location, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !isYAML(path) {
			return nil
		}
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		out = append(out, source{name: path, data: data})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("k8smanifest: walk %q: %w", t.Location, err)
	}
	// Deterministic order regardless of filesystem enumeration.
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

func isYAML(p string) bool {
	ext := strings.ToLower(filepath.Ext(p))
	return ext == ".yaml" || ext == ".yml"
}

// retag rewrites a harden DS-RAT-BOX finding into the k8smanifest namespace and
// records the source file, so results read as manifest findings, not runtime
// ones. The DS-RAT-BOX id is preserved in metadata for traceability.
func retag(f engine.Finding, sourceFile string) engine.Finding {
	f.Module = moduleName
	if f.Metadata == nil {
		f.Metadata = map[string]string{}
	}
	f.Metadata["harden_control"] = f.RuleID
	f.Metadata["source_file"] = sourceFile
	f.RuleID = strings.Replace(f.RuleID, "DS-RAT-BOX-", "DS-RAT-K8S-", 1)
	return f
}

// unwrapTemplate rewrites a workload-controller manifest so the pod spec is at
// the top level, which is what the harden pod parser reads. Deployment /
// StatefulSet / DaemonSet / ReplicaSet / Job put the pod under spec.template;
// CronJob nests it under spec.jobTemplate.spec.template. A bare Pod (or anything
// without a template) is returned unchanged.
func unwrapTemplate(jsonDoc []byte) []byte {
	var obj map[string]any
	if err := json.Unmarshal(jsonDoc, &obj); err != nil {
		return jsonDoc
	}
	spec, ok := obj["spec"].(map[string]any)
	if !ok {
		return jsonDoc
	}

	// CronJob: spec.jobTemplate.spec.template
	if jt, ok := spec["jobTemplate"].(map[string]any); ok {
		if jtSpec, ok := jt["spec"].(map[string]any); ok {
			if tmpl, ok := jtSpec["template"].(map[string]any); ok {
				return liftTemplate(obj, tmpl)
			}
		}
	}
	// Deployment/StatefulSet/DaemonSet/ReplicaSet/Job: spec.template
	if tmpl, ok := spec["template"].(map[string]any); ok {
		return liftTemplate(obj, tmpl)
	}
	return jsonDoc
}

// liftTemplate replaces the object's spec with the template's pod spec, keeping
// the top-level kind/metadata for naming, and re-marshals.
func liftTemplate(obj, tmpl map[string]any) []byte {
	if podSpec, ok := tmpl["spec"].(map[string]any); ok {
		obj["spec"] = podSpec
	}
	// Prefer the template's metadata name/labels if the pod template names itself.
	if tmd, ok := tmpl["metadata"].(map[string]any); ok {
		if _, hasName := tmd["name"]; hasName {
			obj["metadata"] = tmd
		}
	}
	// Force the kind to Pod so the harden probe takes the pod path unambiguously.
	obj["kind"] = "Pod"
	out, err := json.Marshal(obj)
	if err != nil {
		return nil
	}
	return out
}

func parseWarning(name string, docIndex int, err error) engine.Finding {
	return engine.Finding{
		RuleID:      "DS-RAT-K8S-900",
		Module:      moduleName,
		Severity:    engine.SeverityInfo,
		Title:       fmt.Sprintf("Manifest document could not be parsed: %s (doc %d)", name, docIndex),
		Description: err.Error(),
		Resource:    name,
		Remediation: "Fix the YAML syntax, or convert Helm/kustomize output to plain manifests before scanning.",
	}
}

func sortFindings(fs []engine.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].RuleID != fs[j].RuleID {
			return fs[i].RuleID < fs[j].RuleID
		}
		if fs[i].Metadata["source_file"] != fs[j].Metadata["source_file"] {
			return fs[i].Metadata["source_file"] < fs[j].Metadata["source_file"]
		}
		return fs[i].Resource < fs[j].Resource
	})
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
