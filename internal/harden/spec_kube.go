package harden

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// --- Kubernetes Pod parsing --------------------------------------------------
//
// Most people describe a workload as a Pod, so we normalise its (init and
// regular) containers into one Workload each. Kubernetes layers security in two
// places: a pod-level securityContext that sets defaults, and a container-level
// one that overrides for the fields they share (user, seccomp, …). Privilege,
// capabilities, read-only rootfs and privilege-escalation are container-only.
// Volumes are named separately from the mounts that reference them, so we join
// them to recover each mount's host source (that is how a docker.sock hostPath
// becomes visible to the mount checks).

type kubePod struct {
	Kind     string      `json:"kind"`
	Metadata kubeMeta    `json:"metadata"`
	Spec     kubePodSpec `json:"spec"`
}

type kubeMeta struct {
	Name        string            `json:"name"`
	Annotations map[string]string `json:"annotations"`
}

type kubePodSpec struct {
	HostPID          bool            `json:"hostPID"`
	HostIPC          bool            `json:"hostIPC"`
	HostNetwork      bool            `json:"hostNetwork"`
	HostUsers        *bool           `json:"hostUsers"`
	RuntimeClassName string          `json:"runtimeClassName"`
	SecurityContext  *kubePodSecCtx  `json:"securityContext"`
	Containers       []kubeContainer `json:"containers"`
	InitContainers   []kubeContainer `json:"initContainers"`
	Volumes          []kubeVolume    `json:"volumes"`
}

// kubePodSecCtx is the pod-level context: the defaults containers inherit.
type kubePodSecCtx struct {
	RunAsUser      *int64       `json:"runAsUser"`
	RunAsNonRoot   *bool        `json:"runAsNonRoot"`
	SeccompProfile *kubeSeccomp `json:"seccompProfile"`
}

type kubeContainer struct {
	Name            string         `json:"name"`
	Image           string         `json:"image"`
	SecurityContext *kubeCtrSecCtx `json:"securityContext"`
	Resources       kubeResources  `json:"resources"`
	VolumeMounts    []kubeVolMount `json:"volumeMounts"`
	Env             []kubeEnvVar   `json:"env"`
}

type kubeCtrSecCtx struct {
	Privileged               *bool         `json:"privileged"`
	RunAsUser                *int64        `json:"runAsUser"`
	RunAsNonRoot             *bool         `json:"runAsNonRoot"`
	ReadOnlyRootFilesystem   *bool         `json:"readOnlyRootFilesystem"`
	AllowPrivilegeEscalation *bool         `json:"allowPrivilegeEscalation"`
	Capabilities             *kubeCaps     `json:"capabilities"`
	SeccompProfile           *kubeSeccomp  `json:"seccompProfile"`
	AppArmorProfile          *kubeAppArmor `json:"appArmorProfile"`
}

type kubeCaps struct {
	Add  []string `json:"add"`
	Drop []string `json:"drop"`
}

type kubeSeccomp struct {
	Type             string `json:"type"` // RuntimeDefault|Localhost|Unconfined
	LocalhostProfile string `json:"localhostProfile"`
}

type kubeAppArmor struct {
	Type             string `json:"type"` // RuntimeDefault|Localhost|Unconfined
	LocalhostProfile string `json:"localhostProfile"`
}

type kubeResources struct {
	Limits map[string]string `json:"limits"`
}

type kubeVolMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly"`
}

type kubeEnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type kubeVolume struct {
	Name     string        `json:"name"`
	HostPath *kubeHostPath `json:"hostPath"`
}

type kubeHostPath struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

// parseKubePod normalises every container in a Pod into a Workload.
func parseKubePod(data []byte) ([]Workload, error) {
	var pod kubePod
	if err := json.Unmarshal(data, &pod); err != nil {
		return nil, fmt.Errorf("parse Kubernetes pod: %w", err)
	}
	// Nothing to check without containers; treat as "not a spec we handle".
	all := append(append([]kubeContainer(nil), pod.Spec.InitContainers...), pod.Spec.Containers...)
	if len(all) == 0 {
		return nil, nil
	}

	volSource := map[string]string{}
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			volSource[v.Name] = v.HostPath.Path
		}
	}

	out := make([]Workload, 0, len(all))
	for _, c := range all {
		out = append(out, kubeContainerWorkload(&pod, c, volSource))
	}
	return out, nil
}

// kubeContainerWorkload folds pod-level defaults and container-level overrides
// into one normalised Workload.
func kubeContainerWorkload(pod *kubePod, c kubeContainer, volSource map[string]string) Workload {
	w := Workload{
		Source:       "kubernetes",
		Name:         containerName(pod, c),
		Image:        c.Image,
		HostPID:      pod.Spec.HostPID,
		HostIPC:      pod.Spec.HostIPC,
		HostNetwork:  pod.Spec.HostNetwork,
		RuntimeClass: pod.Spec.RuntimeClassName,
		Env:          map[string]string{},
	}
	// hostUsers defaults to true (host user namespace) when unset: userns
	// remapping is opt-in, so an absent field is the insecure default.
	w.HostUsers = pod.Spec.HostUsers == nil || *pod.Spec.HostUsers

	// Start from pod-level defaults, then let the container override.
	pod0 := pod.Spec.SecurityContext
	if pod0 != nil {
		w.RunAsUser = pod0.RunAsUser
		w.RunAsNonRoot = pod0.RunAsNonRoot
		applyKubeSeccomp(&w, pod0.SeccompProfile)
	}

	if sc := c.SecurityContext; sc != nil {
		if sc.Privileged != nil {
			w.Privileged = *sc.Privileged
		}
		if sc.RunAsUser != nil {
			w.RunAsUser = sc.RunAsUser
		}
		if sc.RunAsNonRoot != nil {
			w.RunAsNonRoot = sc.RunAsNonRoot
		}
		if sc.ReadOnlyRootFilesystem != nil {
			w.ReadOnlyRootFS = *sc.ReadOnlyRootFilesystem
		}
		if sc.AllowPrivilegeEscalation != nil {
			w.AllowPrivilegeEscalation = sc.AllowPrivilegeEscalation
			// no-new-privileges is the runtime realisation of !allowPrivilegeEscalation.
			w.NoNewPrivileges = !*sc.AllowPrivilegeEscalation
		}
		if sc.Capabilities != nil {
			w.CapAdd = normalizeCaps(sc.Capabilities.Add)
			w.CapDrop = normalizeCaps(sc.Capabilities.Drop)
		}
		if sc.SeccompProfile != nil {
			applyKubeSeccomp(&w, sc.SeccompProfile)
		}
		applyKubeAppArmor(&w, pod, c, sc.AppArmorProfile)
	} else {
		applyKubeAppArmor(&w, pod, c, nil)
	}

	// Memory limit (pids limits are node-scoped in Kubernetes, so left unset).
	if mem, ok := c.Resources.Limits["memory"]; ok {
		if b, err := parseQuantity(mem); err == nil {
			w.MemoryLimitBytes = b
		}
	}

	for _, vm := range c.VolumeMounts {
		w.Mounts = append(w.Mounts, Mount{
			Source:      volSource[vm.Name],
			Destination: vm.MountPath,
			ReadOnly:    vm.ReadOnly,
			Type:        "bind",
		})
	}
	for _, e := range c.Env {
		w.Env[e.Name] = e.Value
	}
	return w
}

// applyKubeSeccomp maps a Kubernetes seccompProfile onto the normalised model.
func applyKubeSeccomp(w *Workload, sp *kubeSeccomp) {
	if sp == nil {
		return
	}
	switch strings.ToLower(sp.Type) {
	case "unconfined":
		w.Seccomp = SeccompUnconfined
	case "runtimedefault":
		w.Seccomp = SeccompRuntimeDefault
	case "localhost":
		w.Seccomp = SeccompLocalhost
		w.SeccompProfile = sp.LocalhostProfile
	}
}

// applyKubeAppArmor resolves the AppArmor posture from the newer field or the
// legacy per-container annotation, preferring the field.
func applyKubeAppArmor(w *Workload, pod *kubePod, c kubeContainer, ap *kubeAppArmor) {
	if ap != nil {
		switch strings.ToLower(ap.Type) {
		case "unconfined":
			w.AppArmor = "unconfined"
		case "runtimedefault":
			w.AppArmor = "runtime/default"
		case "localhost":
			w.AppArmor = "localhost/" + ap.LocalhostProfile
		}
		return
	}
	// Legacy annotation: container.apparmor.security.beta.kubernetes.io/<name>.
	key := "container.apparmor.security.beta.kubernetes.io/" + c.Name
	if v, ok := pod.Metadata.Annotations[key]; ok {
		w.AppArmor = v
	}
}

// containerName qualifies a container by its pod so findings point somewhere.
func containerName(pod *kubePod, c kubeContainer) string {
	name := c.Name
	if name == "" {
		name = "container"
	}
	if pod.Metadata.Name != "" {
		return pod.Metadata.Name + "/" + name
	}
	return name
}

// parseQuantity converts a Kubernetes memory quantity to bytes. It handles the
// binary suffixes (Ki/Mi/Gi/Ti/Pi), the decimal ones (k/M/G/T/P), and a bare
// integer. Anything it cannot parse returns an error so the caller leaves the
// limit unset rather than trusting a wrong number.
func parseQuantity(q string) (int64, error) {
	q = strings.TrimSpace(q)
	if q == "" {
		return 0, fmt.Errorf("empty quantity")
	}
	binary := map[string]int64{"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30, "Ti": 1 << 40, "Pi": 1 << 50}
	for suf, mult := range binary {
		if strings.HasSuffix(q, suf) {
			n, err := strconv.ParseInt(strings.TrimSuffix(q, suf), 10, 64)
			if err != nil {
				return 0, err
			}
			return n * mult, nil
		}
	}
	decimal := map[byte]int64{'k': 1e3, 'K': 1e3, 'M': 1e6, 'G': 1e9, 'T': 1e12, 'P': 1e15}
	if mult, ok := decimal[q[len(q)-1]]; ok {
		n, err := strconv.ParseInt(q[:len(q)-1], 10, 64)
		if err != nil {
			return 0, err
		}
		return n * mult, nil
	}
	return strconv.ParseInt(q, 10, 64)
}
