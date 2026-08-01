package harden

import (
	"encoding/json"
	"fmt"
	"strings"
)

// --- OCI runtime spec (config.json) parsing ----------------------------------
//
// This is the document runc consumes. Its capability model is an allow-list (a
// bounding set), which we normalise into the add/drop model the checks share by
// treating it as "drop ALL, then add <bounding set>" — an exactly equivalent and
// tidy translation. Its namespace model is inverted from intuition: a namespace
// type LISTED in linux.namespaces is one the container gets its OWN of, so a type
// ABSENT from the list means the container shares the host's. We decode that here
// so the checks can reason in plain "hostPID?" terms.

type ociSpec struct {
	OCIVersion  string            `json:"ociVersion"`
	Process     ociProcess        `json:"process"`
	Root        ociRoot           `json:"root"`
	Mounts      []ociMount        `json:"mounts"`
	Linux       ociLinux          `json:"linux"`
	Annotations map[string]string `json:"annotations"`
}

type ociProcess struct {
	User            ociUser   `json:"user"`
	Env             []string  `json:"env"`
	NoNewPrivileges bool      `json:"noNewPrivileges"`
	Capabilities    ociCapSet `json:"capabilities"`
}

type ociUser struct {
	UID int64 `json:"uid"`
	GID int64 `json:"gid"`
}

type ociCapSet struct {
	Bounding  []string `json:"bounding"`
	Effective []string `json:"effective"`
	Permitted []string `json:"permitted"`
}

type ociRoot struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly"`
}

type ociMount struct {
	Destination string   `json:"destination"`
	Source      string   `json:"source"`
	Type        string   `json:"type"`
	Options     []string `json:"options"`
}

type ociLinux struct {
	Namespaces    []ociNamespace  `json:"namespaces"`
	MaskedPaths   []string        `json:"maskedPaths"`
	ReadonlyPaths []string        `json:"readonlyPaths"`
	UIDMappings   []ociIDMapping  `json:"uidMappings"`
	Resources     *ociResources   `json:"resources"`
	Seccomp       json.RawMessage `json:"seccomp"`
	Devices       []ociDevice     `json:"devices"`
	// MountLabel present on privileged specs; not needed but decoded to avoid
	// silent surprises if we extend later.
}

type ociNamespace struct {
	Type string `json:"type"`
	Path string `json:"path"`
}

type ociIDMapping struct {
	ContainerID int64 `json:"containerID"`
	HostID      int64 `json:"hostID"`
	Size        int64 `json:"size"`
}

type ociResources struct {
	Memory  *ociMemory    `json:"memory"`
	Pids    *ociPids      `json:"pids"`
	Devices []ociDeviceCg `json:"devices"`
}

type ociMemory struct {
	Limit int64 `json:"limit"`
}

type ociPids struct {
	Limit int64 `json:"limit"`
}

// ociDeviceCg is a device-cgroup rule. An {allow:true} rule with no type and
// "rwm" access is the fingerprint of `docker run --privileged` (all devices).
type ociDeviceCg struct {
	Allow  bool   `json:"allow"`
	Type   string `json:"type"`
	Access string `json:"access"`
}

type ociDevice struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

// parseOCISpec normalises an OCI runtime config.json into a Workload.
func parseOCISpec(data []byte) (*Workload, error) {
	var s ociSpec
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse OCI runtime spec: %w", err)
	}

	w := &Workload{
		Source:          "oci",
		Name:            ociName(&s),
		NoNewPrivileges: s.Process.NoNewPrivileges,
		ReadOnlyRootFS:  s.Root.Readonly,
		RunAsUser:       int64Ptr(s.Process.User.UID),
		Env:             parseEnvList(s.Process.Env),
	}

	// Capabilities: the bounding set is what the process can ever hold. Model it
	// as drop-ALL + add(bounding) so the shared checks read it correctly.
	held := s.Process.Capabilities.Bounding
	if len(held) == 0 {
		held = s.Process.Capabilities.Effective
	}
	w.CapDrop = []string{"ALL"}
	w.CapAdd = normalizeCaps(held)

	// Namespaces: absent type ⇒ shares the host's.
	own := map[string]bool{}
	for _, ns := range s.Linux.Namespaces {
		own[strings.ToLower(ns.Type)] = true
	}
	w.HostPID = !own["pid"]
	w.HostIPC = !own["ipc"]
	w.HostNetwork = !own["network"]
	// User namespace: own "user" ns or explicit uid mappings both mean remapped.
	w.HostUsers = !(own["user"] || len(s.Linux.UIDMappings) > 0)

	// Seccomp: an absent linux.seccomp block means runc applies no filter (the
	// spec asserts nothing). We distinguish that "unset" from an explicit profile.
	if len(s.Linux.Seccomp) == 0 || string(s.Linux.Seccomp) == "null" {
		w.Seccomp = SeccompUnset
	} else {
		w.Seccomp = SeccompCustom
	}

	// AppArmor rides in annotations on an OCI spec.
	if p := s.Annotations["org.opencontainers.image.apparmorProfile"]; p != "" {
		w.AppArmor = p
	}

	// Resources.
	if s.Linux.Resources != nil {
		if s.Linux.Resources.Memory != nil {
			w.MemoryLimitBytes = s.Linux.Resources.Memory.Limit
		}
		if s.Linux.Resources.Pids != nil {
			w.PidsLimit = s.Linux.Resources.Pids.Limit
		}
		// Privileged fingerprint: a blanket allow-all device rule.
		for _, d := range s.Linux.Resources.Devices {
			if d.Allow && d.Type == "" && coversRWM(d.Access) {
				w.Privileged = true
			}
		}
	}

	w.MaskedPaths = append([]string(nil), s.Linux.MaskedPaths...)
	w.ReadonlyPaths = append([]string(nil), s.Linux.ReadonlyPaths...)

	for _, m := range s.Mounts {
		w.Mounts = append(w.Mounts, Mount{
			Source:      m.Source,
			Destination: m.Destination,
			Type:        m.Type,
			ReadOnly:    hasOption(m.Options, "ro"),
		})
	}
	for _, d := range s.Linux.Devices {
		w.Devices = append(w.Devices, Device{Path: d.Path, Type: d.Type})
	}

	if v, ok := w.Env["NVIDIA_VISIBLE_DEVICES"]; ok {
		_ = v // consumed by the GPU check; kept in Env
	}
	return w, nil
}

// ociName picks a human label from annotations, falling back to a constant.
func ociName(s *ociSpec) string {
	for _, k := range []string{"io.kubernetes.cri.container-name", "org.opencontainers.image.title"} {
		if v := s.Annotations[k]; v != "" {
			return v
		}
	}
	return "oci-container"
}

// coversRWM reports whether a device-cgroup access string grants read+write+mknod
// (an empty access string also means "all" in the cgroup device model).
func coversRWM(access string) bool {
	if access == "" {
		return true
	}
	return strings.Contains(access, "r") && strings.Contains(access, "w") && strings.Contains(access, "m")
}

// hasOption reports whether a mount option list contains opt.
func hasOption(opts []string, opt string) bool {
	for _, o := range opts {
		if o == opt {
			return true
		}
	}
	return false
}

// parseEnvList turns ["K=v", ...] into a map, keeping the last value on repeats.
func parseEnvList(env []string) map[string]string {
	if len(env) == 0 {
		return nil
	}
	out := make(map[string]string, len(env))
	for _, e := range env {
		if i := strings.IndexByte(e, '='); i >= 0 {
			out[e[:i]] = e[i+1:]
		}
	}
	return out
}
