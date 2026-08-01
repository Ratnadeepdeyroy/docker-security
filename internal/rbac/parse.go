package rbac

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// This file turns Kubernetes JSON (and our small Docker-host descriptor) into the
// normalized Cluster model. We parse JSON only — the standard library has no YAML
// reader and this wave is stdlib-only — which is fine in practice: `kubectl get
// … -o json` and audit exports are already JSON, and requiring JSON keeps the
// parser small and the input unambiguous. Parsing is bounded (file size and
// count caps) so a hostile or accidental giant tree can never exhaust memory.

// --- Bounds --------------------------------------------------------------

const (
	// maxFileBytes caps a single JSON document. RBAC exports are small; anything
	// larger is either not ours or an attempt to blow up memory.
	maxFileBytes = 8 << 20 // 8 MiB
	// maxFiles caps how many files a directory walk will read, so pointing the
	// scanner at a huge tree degrades gracefully instead of hanging.
	maxFiles = 5000
)

// --- Public entry points -------------------------------------------------

// LoadBytes parses a single JSON document (an object or a Kubernetes List) into
// a Cluster. Unknown kinds are ignored, not errored: real exports mix in objects
// we do not model, and dropping them is the correct, quiet behavior.
func LoadBytes(data []byte) (*Cluster, error) {
	c := newCluster()
	if err := ingest(c, data); err != nil {
		return nil, err
	}
	return c, nil
}

// LoadPath loads from a file or, if path is a directory, every *.json file under
// it (bounded). It is the entry point the `dsecrat rbac <path>` command uses.
func LoadPath(path string) (*Cluster, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat rbac input %q: %w", path, err)
	}
	c := newCluster()
	if !info.IsDir() {
		if err := ingestFile(c, path); err != nil {
			return nil, err
		}
		return c, nil
	}
	count := 0
	walkErr := filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}
		if count >= maxFiles {
			return fs.SkipAll
		}
		count++
		// A single unreadable/oversized file must not fail the whole scan; skip
		// it and keep going, matching the engine's "partial results" principle.
		if err := ingestFile(c, p); err != nil {
			return nil
		}
		return nil
	})
	if walkErr != nil {
		return nil, fmt.Errorf("walk rbac dir %q: %w", path, walkErr)
	}
	return c, nil
}

// ingestFile reads and ingests one file, enforcing the size cap.
func ingestFile(c *Cluster, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %q: %w", path, err)
	}
	if info.Size() > maxFileBytes {
		return fmt.Errorf("rbac input %q exceeds %d bytes", path, maxFileBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %q: %w", path, err)
	}
	return ingest(c, data)
}

// --- JSON shapes (upstream schema, only the fields we need) --------------

// rawObject is the discriminated union we decode into: kind selects which of the
// remaining fields are meaningful. Using one struct with json omitempty keeps the
// parser to a single Unmarshal pass per object.
type rawObject struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name        string            `json:"name"`
		Namespace   string            `json:"namespace"`
		Labels      map[string]string `json:"labels"`
		Annotations map[string]string `json:"annotations"`
	} `json:"metadata"`
	// List
	Items []json.RawMessage `json:"items"`
	// Role / ClusterRole
	Rules           []rawRule `json:"rules"`
	AggregationRule *struct{} `json:"aggregationRule"`
	// RoleBinding / ClusterRoleBinding
	Subjects []rawSubject `json:"subjects"`
	RoleRef  *struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	} `json:"roleRef"`
	// ServiceAccount
	AutomountServiceAccountToken *bool `json:"automountServiceAccountToken"`
	// Pod
	Spec *rawPodSpec `json:"spec"`
	// Docker-host descriptor (our own kind)
	DockerGroupMembers []string         `json:"dockerGroupMembers"`
	Rootless           bool             `json:"rootless"`
	SocketMounts       []rawSocketMount `json:"socketMounts"`
	// Optional per-object usage annotation for least-privilege / dormancy.
	LastUsedUnix int64 `json:"lastUsedUnix"`
	// Optional explicit cloud-IAM binding descriptor. When present it augments
	// (and can override) what is inferred from workload-identity annotations,
	// carrying the bound role's privilege level and trust-policy scoping.
	Cloud *rawCloud `json:"cloud"`
}

type rawCloud struct {
	Provider               string `json:"provider"`
	Role                   string `json:"role"`
	Privilege              string `json:"privilege"`
	TrustAnyServiceAccount bool   `json:"trustAnyServiceAccount"`
}

type rawRule struct {
	APIGroups       []string `json:"apiGroups"`
	Resources       []string `json:"resources"`
	ResourceNames   []string `json:"resourceNames"`
	Verbs           []string `json:"verbs"`
	NonResourceURLs []string `json:"nonResourceURLs"`
}

type rawSubject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type rawSocketMount struct {
	Container string `json:"container"`
	Path      string `json:"path"`
}

type rawPodSpec struct {
	ServiceAccountName           string `json:"serviceAccountName"`
	AutomountServiceAccountToken *bool  `json:"automountServiceAccountToken"`
	HostPID                      bool   `json:"hostPID"`
	HostNetwork                  bool   `json:"hostNetwork"`
	Volumes                      []struct {
		HostPath *struct {
			Path string `json:"path"`
		} `json:"hostPath"`
	} `json:"volumes"`
	Containers []rawContainer `json:"containers"`
}

type rawContainer struct {
	SecurityContext *struct {
		Privileged   *bool `json:"privileged"`
		Capabilities *struct {
			Add []string `json:"add"`
		} `json:"capabilities"`
	} `json:"securityContext"`
}

// --- Ingest --------------------------------------------------------------

// ingest decodes one document. A List is expanded into its items; a bare object
// is dispatched by kind. Malformed top-level JSON is an error (the caller gave us
// junk); malformed items inside a List are skipped (one bad object shouldn't sink
// a whole export).
func ingest(c *Cluster, data []byte) error {
	var obj rawObject
	if err := json.Unmarshal(data, &obj); err != nil {
		return fmt.Errorf("parse rbac json: %w", err)
	}
	if strings.EqualFold(obj.Kind, "List") || len(obj.Items) > 0 {
		for _, item := range obj.Items {
			var child rawObject
			if err := json.Unmarshal(item, &child); err != nil {
				continue
			}
			dispatch(c, &child)
		}
		return nil
	}
	dispatch(c, &obj)
	return nil
}

// dispatch routes one parsed object into the Cluster by its kind.
func dispatch(c *Cluster, o *rawObject) {
	switch o.Kind {
	case "Role", "ClusterRole":
		cluster := o.Kind == "ClusterRole"
		r := &Role{
			Name:          o.Metadata.Name,
			Namespace:     o.Metadata.Namespace,
			ClusterScoped: cluster,
			Labels:        o.Metadata.Labels,
			Aggregates:    o.AggregationRule != nil,
		}
		for _, rr := range o.Rules {
			r.Rules = append(r.Rules, PolicyRule{
				APIGroups:       rr.APIGroups,
				Resources:       rr.Resources,
				ResourceNames:   rr.ResourceNames,
				Verbs:           rr.Verbs,
				NonResourceURLs: rr.NonResourceURLs,
			})
		}
		c.Roles[roleKey(cluster, r.Namespace, r.Name)] = r

	case "RoleBinding", "ClusterRoleBinding":
		b := &Binding{
			Name:          o.Metadata.Name,
			Namespace:     o.Metadata.Namespace,
			ClusterScoped: o.Kind == "ClusterRoleBinding",
		}
		for _, s := range o.Subjects {
			b.Subjects = append(b.Subjects, Subject{Kind: s.Kind, Name: s.Name, Namespace: s.Namespace})
		}
		if o.RoleRef != nil {
			b.RoleRef = RoleRef{Kind: o.RoleRef.Kind, Name: o.RoleRef.Name}
		}
		c.Bindings = append(c.Bindings, b)

	case "ServiceAccount":
		c.ServiceAccounts[o.Metadata.Namespace+"/"+o.Metadata.Name] = &ServiceAccount{
			Name:           o.Metadata.Name,
			Namespace:      o.Metadata.Namespace,
			AutomountToken: o.AutomountServiceAccountToken,
			Labels:         o.Metadata.Labels,
			LastUsedUnix:   o.LastUsedUnix,
			Cloud:          cloudIdentity(o),
		}

	case "Pod":
		c.Pods = append(c.Pods, parsePod(o))

	case "DockerHost":
		h := &DockerHost{
			Name:               o.Metadata.Name,
			DockerGroupMembers: o.DockerGroupMembers,
			Rootless:           o.Rootless,
		}
		for _, m := range o.SocketMounts {
			h.SocketMounts = append(h.SocketMounts, SocketMount{Container: m.Container, Path: m.Path})
		}
		c.DockerHosts = append(c.DockerHosts, h)
	}
}

// parsePod flattens a pod spec into the escalation-relevant Pod model, hoisting
// the strongest security context across all containers (any privileged container
// makes the pod privileged for our purposes).
func parsePod(o *rawObject) *Pod {
	p := &Pod{Name: o.Metadata.Name, Namespace: o.Metadata.Namespace}
	if o.Spec == nil {
		return p
	}
	p.ServiceAccountName = o.Spec.ServiceAccountName
	p.AutomountToken = o.Spec.AutomountServiceAccountToken
	p.HostPID = o.Spec.HostPID
	p.HostNetwork = o.Spec.HostNetwork
	for _, v := range o.Spec.Volumes {
		if v.HostPath != nil {
			p.HostPathMounts = append(p.HostPathMounts, v.HostPath.Path)
		}
	}
	for _, ct := range o.Spec.Containers {
		if ct.SecurityContext == nil {
			continue
		}
		if ct.SecurityContext.Privileged != nil && *ct.SecurityContext.Privileged {
			p.Privileged = true
		}
		if ct.SecurityContext.Capabilities != nil {
			p.AddedCapabilities = append(p.AddedCapabilities, ct.SecurityContext.Capabilities.Add...)
		}
	}
	return p
}
