// Package kubebench assesses a Kubernetes cluster against a subset of the CIS
// Kubernetes Benchmark (CAPABILITY_SPEC domain 10). Like dockerbench it is a
// read-only auditor that runs against a collected evidence snapshot — control-
// plane component flags, kubelet config, file permissions, and RBAC/pod-security
// objects — so assessment is deterministic and works offline. On a live cluster
// a collector produces the same document from the API server, the static-pod
// manifests, and the node config; tests commit it as a fixture.
//
// The benchmark is version- and platform-aware: the profile machinery
// (profile.go) picks a version-matched CIS revision and, on managed clusters
// (EKS/GKE/AKS), scopes scoring to the controls the customer actually owns.
package kubebench

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// maxEvidenceBytes bounds evidence reads so a hostile document cannot exhaust
// memory. A cluster snapshot with RBAC can be large, so this is generous.
const maxEvidenceBytes = 32 << 20

// Evidence is the offline-assessable snapshot of a Kubernetes cluster.
type Evidence struct {
	// Version is the reported Kubernetes server version, e.g. "1.29.3". Used to
	// select the version-matched benchmark profile.
	Version string `json:"version,omitempty"`
	// Platform is the distribution: "self-managed", "eks", "gke", "aks", or ""
	// (auto-detected as self-managed). Drives managed-variant scoping.
	Platform string `json:"platform,omitempty"`

	APIServer         Component `json:"apiserver,omitempty"`
	ControllerManager Component `json:"controller_manager,omitempty"`
	Scheduler         Component `json:"scheduler,omitempty"`
	Etcd              Component `json:"etcd,omitempty"`
	Kubelet           Component `json:"kubelet,omitempty"`

	// Files are permission/ownership stats for manifests and config files.
	Files []FileStat `json:"files,omitempty"`
	// RBAC is a reduced view of cluster roles/bindings and service accounts.
	RBAC RBAC `json:"rbac,omitempty"`
	// PodSecurity captures the Pod Security Admission posture.
	PodSecurity PodSecurity `json:"pod_security,omitempty"`
	// NetworkPolicyNamespaces lists namespaces that have at least one
	// NetworkPolicy; namespaces absent here are treated as having none.
	NetworkPolicyNamespaces []string `json:"network_policy_namespaces,omitempty"`
	// Namespaces is the set of (non-system) namespaces, for default-namespace checks.
	Namespaces []string `json:"namespaces,omitempty"`

	Notes []string `json:"notes,omitempty"`
}

// Component is one control-plane/node binary's effective command-line flags,
// keyed without the leading "--". List-valued flags keep their comma form.
type Component struct {
	Flags map[string]string `json:"flags,omitempty"`
}

// flag returns a flag value and whether it was set.
func (c Component) flag(name string) (string, bool) {
	if c.Flags == nil {
		return "", false
	}
	v, ok := c.Flags[name]
	return v, ok
}

// present reports whether a flag was set at all.
func (c Component) present(name string) bool {
	_, ok := c.flag(name)
	return ok
}

// flagList splits a comma-separated flag value into its members.
func (c Component) flagList(name string) []string {
	v, ok := c.flag(name)
	if !ok || v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// hasFlags reports whether any flags were collected for this component (used to
// distinguish "provider-managed / not collected" from "collected and empty").
func (c Component) hasFlags() bool { return len(c.Flags) > 0 }

// FileStat is a config file's ownership and mode (octal string).
type FileStat struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Mode   string `json:"mode,omitempty"`
	Owner  string `json:"owner,omitempty"`
	Group  string `json:"group,omitempty"`
}

// RBAC is the least-privilege-relevant slice of cluster authorization state.
type RBAC struct {
	ClusterRoleBindings []RoleBinding    `json:"cluster_role_bindings,omitempty"`
	Roles               []Role           `json:"roles,omitempty"`
	ServiceAccounts     []ServiceAccount `json:"service_accounts,omitempty"`
}

// RoleBinding binds subjects to a role (RoleRef is "ClusterRole/name" etc.).
type RoleBinding struct {
	Name     string    `json:"name"`
	RoleRef  string    `json:"role_ref"`
	Subjects []Subject `json:"subjects,omitempty"`
}

// Subject is a binding target (User/Group/ServiceAccount).
type Subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// Role is a (cluster)role reduced to its rules.
type Role struct {
	Name  string       `json:"name"`
	Rules []PolicyRule `json:"rules,omitempty"`
}

// PolicyRule mirrors an RBAC rule (apiGroups/resources/verbs).
type PolicyRule struct {
	APIGroups []string `json:"api_groups,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Verbs     []string `json:"verbs,omitempty"`
}

// ServiceAccount records automount posture for the default-SA checks.
type ServiceAccount struct {
	Namespace                    string `json:"namespace"`
	Name                         string `json:"name"`
	AutomountServiceAccountToken *bool  `json:"automount_service_account_token,omitempty"`
}

// PodSecurity captures the Pod Security Admission posture.
type PodSecurity struct {
	// AdmissionEnabled is true when the PodSecurity admission plugin is on.
	AdmissionEnabled bool `json:"admission_enabled,omitempty"`
	// NamespaceEnforce maps namespace → the enforce level label value
	// (privileged|baseline|restricted). Missing means unlabeled.
	NamespaceEnforce map[string]string `json:"namespace_enforce,omitempty"`
}

// Load reads an evidence document. Accepts a JSON file or a directory holding
// `evidence.json`. A missing path yields an empty Evidence with a Note so the
// caller degrades to INFO rather than crashing.
func Load(path string) (*Evidence, error) {
	if path == "" {
		return &Evidence{Notes: []string{"no evidence path provided"}}, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return &Evidence{Notes: []string{fmt.Sprintf("evidence path %q not found: %v", path, err)}}, nil
	}
	target := path
	if info.IsDir() {
		target = filepath.Join(path, "evidence.json")
		if !fileExists(target) {
			return &Evidence{Notes: []string{fmt.Sprintf("no evidence.json under %q", path)}}, nil
		}
	}

	data, err := readCapped(target)
	if err != nil {
		return nil, fmt.Errorf("read evidence %q: %w", target, err)
	}
	var ev Evidence
	if err := json.Unmarshal(data, &ev); err != nil {
		return nil, fmt.Errorf("parse evidence %q: %w", target, err)
	}
	return &ev, nil
}

func readCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, maxEvidenceBytes))
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

// file returns the stat for a path and whether it was collected.
func (e *Evidence) file(path string) (FileStat, bool) {
	for _, f := range e.Files {
		if f.Path == path {
			return f, true
		}
	}
	return FileStat{}, false
}

// hasEvidence reports whether there is anything to assess, so the module stays
// quiet on a filesystem scan that is not a cluster snapshot.
func (e *Evidence) hasEvidence() bool {
	return e.Version != "" || e.APIServer.hasFlags() || e.Etcd.hasFlags() ||
		e.Kubelet.hasFlags() || len(e.Files) > 0 || len(e.RBAC.ClusterRoleBindings) > 0 ||
		len(e.RBAC.Roles) > 0 || len(e.Namespaces) > 0
}
