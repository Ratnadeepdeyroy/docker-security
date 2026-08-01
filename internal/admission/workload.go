package admission

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/policy"
)

// --- Extracting a workload from a Kubernetes object ------------------------
//
// A ValidatingWebhook may be sent a Pod directly or any controller that embeds a
// pod template (Deployment, StatefulSet, DaemonSet, ReplicaSet, Job, CronJob).
// We locate the PodSpec wherever it lives and flatten its security-relevant
// fields into a policy.Workload, plus the set of container images. The flatten
// is deliberately conservative (PSS-style): where a field is ambiguous we err
// toward "unsafe" so the policy sees the risk rather than a false clean.

// workloadInfo is the extracted view: the flattened workload plus its images.
type workloadInfo struct {
	workload policy.Workload
	images   []string
}

// --- minimal typed pod structures (only the fields policy cares about) ------

type k8sObject struct {
	Kind string          `json:"kind"`
	Spec json.RawMessage `json:"spec"`
}

type podSpec struct {
	Containers          []container         `json:"containers"`
	InitContainers      []container         `json:"initContainers"`
	EphemeralContainers []container         `json:"ephemeralContainers"`
	Volumes             []volume            `json:"volumes"`
	HostNetwork         bool                `json:"hostNetwork"`
	HostPID             bool                `json:"hostPID"`
	HostIPC             bool                `json:"hostIPC"`
	SecurityContext     *podSecurityContext `json:"securityContext"`
}

type container struct {
	Name            string           `json:"name"`
	Image           string           `json:"image"`
	SecurityContext *securityContext `json:"securityContext"`
}

type securityContext struct {
	Privileged               *bool         `json:"privileged"`
	RunAsNonRoot             *bool         `json:"runAsNonRoot"`
	RunAsUser                *int64        `json:"runAsUser"`
	ReadOnlyRootFilesystem   *bool         `json:"readOnlyRootFilesystem"`
	AllowPrivilegeEscalation *bool         `json:"allowPrivilegeEscalation"`
	Capabilities             *capabilities `json:"capabilities"`
}

type podSecurityContext struct {
	RunAsNonRoot *bool  `json:"runAsNonRoot"`
	RunAsUser    *int64 `json:"runAsUser"`
}

type capabilities struct {
	Add  []string `json:"add"`
	Drop []string `json:"drop"`
}

type volume struct {
	Name     string          `json:"name"`
	HostPath *hostPathVolume `json:"hostPath"`
}

type hostPathVolume struct {
	Path string `json:"path"`
}

// extractWorkload parses a raw admission object and flattens its pod spec. A
// malformed object is an error (the caller fails closed); an object with no pod
// spec (e.g. an unexpected kind) yields a not-present workload rather than an
// error, so a policy simply finds nothing to check.
func extractWorkload(raw json.RawMessage) (workloadInfo, error) {
	if len(raw) == 0 {
		return workloadInfo{}, fmt.Errorf("admission object is empty")
	}
	var obj k8sObject
	if err := json.Unmarshal(raw, &obj); err != nil {
		return workloadInfo{}, fmt.Errorf("parse admission object: %w", err)
	}
	spec, err := locatePodSpec(obj)
	if err != nil {
		return workloadInfo{}, err
	}
	if spec == nil {
		return workloadInfo{workload: policy.Workload{Present: false}}, nil
	}
	return flatten(spec), nil
}

// locatePodSpec finds the PodSpec inside a known workload kind. The template
// path differs per controller; CronJob nests one level deeper than the rest.
func locatePodSpec(obj k8sObject) (*podSpec, error) {
	switch obj.Kind {
	case "Pod":
		var ps podSpec
		if err := json.Unmarshal(obj.Spec, &ps); err != nil {
			return nil, fmt.Errorf("parse pod spec: %w", err)
		}
		return &ps, nil
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "ReplicationController", "Job":
		var s struct {
			Template struct {
				Spec podSpec `json:"spec"`
			} `json:"template"`
		}
		if err := json.Unmarshal(obj.Spec, &s); err != nil {
			return nil, fmt.Errorf("parse %s template: %w", obj.Kind, err)
		}
		return &s.Template.Spec, nil
	case "CronJob":
		var s struct {
			JobTemplate struct {
				Spec struct {
					Template struct {
						Spec podSpec `json:"spec"`
					} `json:"template"`
				} `json:"spec"`
			} `json:"jobTemplate"`
		}
		if err := json.Unmarshal(obj.Spec, &s); err != nil {
			return nil, fmt.Errorf("parse CronJob template: %w", err)
		}
		return &s.JobTemplate.Spec.Template.Spec, nil
	default:
		return nil, nil // not a pod-bearing kind
	}
}

// flatten reduces a pod spec to the policy.Workload the engine evaluates.
func flatten(ps *podSpec) workloadInfo {
	all := append(append(append([]container{}, ps.Containers...), ps.InitContainers...), ps.EphemeralContainers...)

	w := policy.Workload{
		Present:     true,
		HostNetwork: ps.HostNetwork,
		HostPID:     ps.HostPID,
		HostIPC:     ps.HostIPC,
		// Read-only-root and non-escalation are guarantees: they only hold if
		// EVERY workload container asserts them. Start true and clear on the
		// first container that does not.
		ReadOnlyRootFS: len(all) > 0,
	}

	var images []string
	for _, c := range all {
		if c.Image != "" {
			images = append(images, c.Image)
		}
		sc := c.SecurityContext
		if sc != nil && sc.Privileged != nil && *sc.Privileged {
			w.Privileged = true
		}
		if !guaranteedNonRoot(sc, ps.SecurityContext) {
			w.RunAsRoot = true
		}
		if !readOnlyRoot(sc) {
			w.ReadOnlyRootFS = false
		}
		if allowsEscalation(sc) {
			w.AllowPrivilegeEscalation = true
		}
		if sc != nil && sc.Capabilities != nil {
			for _, capName := range sc.Capabilities.Add {
				if !hasCap(w.Capabilities, capName) {
					w.Capabilities = append(w.Capabilities, capName)
				}
			}
		}
	}
	for _, v := range ps.Volumes {
		if v.HostPath != nil {
			w.UsesHostPath = true
		}
	}
	w.Images = images
	return workloadInfo{workload: w, images: images}
}

// guaranteedNonRoot reports whether a container is guaranteed not to run as
// root, honoring the container context then the pod default. Absent an explicit
// guarantee we assume it may be root (the conservative PSS reading).
func guaranteedNonRoot(sc *securityContext, pod *podSecurityContext) bool {
	nonRoot := containerBool(scRunAsNonRoot(sc), podRunAsNonRoot(pod))
	if nonRoot != nil && *nonRoot {
		return true
	}
	uid := containerInt(scRunAsUser(sc), podRunAsUser(pod))
	return uid != nil && *uid != 0
}

// readOnlyRoot reports whether a container asserts a read-only root filesystem.
func readOnlyRoot(sc *securityContext) bool {
	return sc != nil && sc.ReadOnlyRootFilesystem != nil && *sc.ReadOnlyRootFilesystem
}

// allowsEscalation reports whether a container permits privilege escalation.
// Kubernetes defaults this to true, so anything not explicitly false counts.
func allowsEscalation(sc *securityContext) bool {
	if sc == nil || sc.AllowPrivilegeEscalation == nil {
		return true
	}
	return *sc.AllowPrivilegeEscalation
}

// --- small nil-safe accessors ----------------------------------------------

func scRunAsNonRoot(sc *securityContext) *bool {
	if sc == nil {
		return nil
	}
	return sc.RunAsNonRoot
}
func scRunAsUser(sc *securityContext) *int64 {
	if sc == nil {
		return nil
	}
	return sc.RunAsUser
}
func podRunAsNonRoot(p *podSecurityContext) *bool {
	if p == nil {
		return nil
	}
	return p.RunAsNonRoot
}
func podRunAsUser(p *podSecurityContext) *int64 {
	if p == nil {
		return nil
	}
	return p.RunAsUser
}

func containerBool(c, pod *bool) *bool {
	if c != nil {
		return c
	}
	return pod
}
func containerInt(c, pod *int64) *int64 {
	if c != nil {
		return c
	}
	return pod
}

func hasCap(caps []string, want string) bool {
	for _, c := range caps {
		if strings.EqualFold(c, want) {
			return true
		}
	}
	return false
}

// parseImageRef splits an image reference into registry/repository/tag/digest,
// applying Docker Hub defaults, so a policy can gate on registry and pinning.
func parseImageRef(ref string) policy.Image {
	img := policy.Image{Reference: ref}
	rest := ref
	if i := strings.Index(rest, "@"); i >= 0 {
		img.Digest = rest[i+1:]
		rest = rest[:i]
	}
	if slash := strings.Index(rest, "/"); slash >= 0 {
		first := rest[:slash]
		if strings.ContainsAny(first, ".:") || first == "localhost" {
			img.Registry = first
			rest = rest[slash+1:]
		} else {
			img.Registry = "docker.io"
		}
	} else {
		img.Registry = "docker.io"
	}
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		img.Tag = rest[i+1:]
		rest = rest[:i]
	}
	img.Repository = rest
	return img
}
