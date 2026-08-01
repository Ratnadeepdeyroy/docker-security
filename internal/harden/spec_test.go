package harden

import "testing"

// A hardened OCI runtime spec: non-root, ro rootfs, drops caps to nothing,
// own namespaces + uid mappings, seccomp present, mem/pids limits, masked paths.
const hardenedOCI = `{
  "ociVersion": "1.0.2",
  "process": {
    "user": {"uid": 1000, "gid": 1000},
    "noNewPrivileges": true,
    "capabilities": {"bounding": [], "effective": []},
    "env": ["PATH=/usr/bin"]
  },
  "root": {"path": "rootfs", "readonly": true},
  "mounts": [{"destination": "/data", "source": "/srv/data", "type": "bind", "options": ["ro", "nosuid"]}],
  "linux": {
    "namespaces": [{"type": "pid"}, {"type": "network"}, {"type": "ipc"}, {"type": "mount"}, {"type": "uts"}, {"type": "user"}],
    "uidMappings": [{"containerID": 0, "hostID": 100000, "size": 65536}],
    "maskedPaths": ["/proc/kcore", "/proc/sysrq-trigger"],
    "readonlyPaths": ["/proc/sys"],
    "seccomp": {"defaultAction": "SCMP_ACT_ERRNO"},
    "resources": {"memory": {"limit": 536870912}, "pids": {"limit": 100}}
  }
}`

// A privileged OCI spec: the blanket allow-all device rule, no namespaces listed
// (so all host namespaces are shared), a huge cap set, no seccomp, no masks.
const privilegedOCI = `{
  "ociVersion": "1.0.2",
  "process": {
    "user": {"uid": 0, "gid": 0},
    "noNewPrivileges": false,
    "capabilities": {"bounding": ["CAP_SYS_ADMIN", "CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_CHOWN"]}
  },
  "root": {"path": "rootfs", "readonly": false},
  "mounts": [{"destination": "/host", "source": "/", "type": "bind", "options": ["rw"]}],
  "linux": {
    "namespaces": [{"type": "mount"}],
    "resources": {"devices": [{"allow": true, "access": "rwm"}]}
  }
}`

func TestParseOCIHardened(t *testing.T) {
	ws, err := Parse([]byte(hardenedOCI))
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 1 {
		t.Fatalf("want 1 workload, got %d", len(ws))
	}
	w := ws[0]
	if w.Source != "oci" {
		t.Errorf("source = %q, want oci", w.Source)
	}
	if !w.NoNewPrivileges || !w.ReadOnlyRootFS {
		t.Errorf("expected noNewPrivileges & readOnlyRootFS")
	}
	if w.RunAsUser == nil || *w.RunAsUser != 1000 {
		t.Errorf("runAsUser = %v, want 1000", w.RunAsUser)
	}
	if w.HostPID || w.HostNetwork || w.HostIPC || w.HostUsers {
		t.Errorf("hardened spec must not share host namespaces: %+v", w)
	}
	if !containsFold(w.CapDrop, "ALL") || len(w.CapAdd) != 0 {
		t.Errorf("expected drop-ALL and no added caps, got add=%v drop=%v", w.CapAdd, w.CapDrop)
	}
	if w.Seccomp != SeccompCustom {
		t.Errorf("seccomp = %q, want custom (present)", w.Seccomp)
	}
	if w.MemoryLimitBytes != 536870912 || w.PidsLimit != 100 {
		t.Errorf("limits mem=%d pids=%d", w.MemoryLimitBytes, w.PidsLimit)
	}
	if len(w.MaskedPaths) == 0 {
		t.Errorf("expected masked paths")
	}
}

func TestParseOCIPrivileged(t *testing.T) {
	ws, err := Parse([]byte(privilegedOCI))
	if err != nil {
		t.Fatal(err)
	}
	w := ws[0]
	if !w.Privileged {
		t.Errorf("allow-all device rule should mark the workload privileged")
	}
	// No pid/network/ipc namespace listed ⇒ shares the host's.
	if !w.HostPID || !w.HostNetwork || !w.HostIPC {
		t.Errorf("absent namespaces must map to host sharing: %+v", w)
	}
	if !containsFold(w.CapAdd, "SYS_ADMIN") {
		t.Errorf("expected SYS_ADMIN in held caps, got %v", w.CapAdd)
	}
	if w.Seccomp != SeccompUnset {
		t.Errorf("no seccomp block ⇒ SeccompUnset, got %q", w.Seccomp)
	}
	if len(w.Mounts) != 1 || w.Mounts[0].Source != "/" {
		t.Errorf("expected a host-root bind mount, got %+v", w.Mounts)
	}
}

const insecureKubePod = `{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {"name": "web"},
  "spec": {
    "hostPID": true,
    "runtimeClassName": "runc",
    "securityContext": {"runAsUser": 1000, "seccompProfile": {"type": "RuntimeDefault"}},
    "containers": [
      {
        "name": "app",
        "image": "nginx:latest",
        "securityContext": {
          "privileged": true,
          "runAsUser": 0,
          "allowPrivilegeEscalation": true,
          "capabilities": {"add": ["NET_ADMIN", "SYS_ADMIN"], "drop": ["ALL"]},
          "seccompProfile": {"type": "Unconfined"}
        },
        "resources": {"limits": {"memory": "256Mi"}},
        "volumeMounts": [{"name": "dsock", "mountPath": "/var/run/docker.sock"}]
      }
    ],
    "volumes": [{"name": "dsock", "hostPath": {"path": "/var/run/docker.sock"}}]
  }
}`

func TestParseKubePodOverridesAndJoins(t *testing.T) {
	ws, err := Parse([]byte(insecureKubePod))
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 1 {
		t.Fatalf("want 1 container workload, got %d", len(ws))
	}
	w := ws[0]
	if w.Name != "web/app" {
		t.Errorf("name = %q, want web/app", w.Name)
	}
	if !w.Privileged {
		t.Errorf("container privileged flag lost")
	}
	// Container securityContext (runAsUser 0) overrides pod-level (1000).
	if w.RunAsUser == nil || *w.RunAsUser != 0 {
		t.Errorf("container override lost: runAsUser = %v, want 0", w.RunAsUser)
	}
	// Container seccomp Unconfined overrides pod RuntimeDefault.
	if w.Seccomp != SeccompUnconfined {
		t.Errorf("seccomp = %q, want unconfined (container override)", w.Seccomp)
	}
	// allowPrivilegeEscalation:true ⇒ no-new-privileges false.
	if w.NoNewPrivileges {
		t.Errorf("allowPrivilegeEscalation:true should map to noNewPrivileges:false")
	}
	// Volume→volumeMount join recovers the docker.sock host source.
	if len(w.Mounts) != 1 || w.Mounts[0].Source != "/var/run/docker.sock" {
		t.Errorf("docker.sock hostPath not joined to mount: %+v", w.Mounts)
	}
	if w.HostPID != true {
		t.Errorf("pod-level hostPID not propagated")
	}
	if w.MemoryLimitBytes != 256*(1<<20) {
		t.Errorf("memory limit = %d, want %d", w.MemoryLimitBytes, 256*(1<<20))
	}
}

func TestParseQuantity(t *testing.T) {
	cases := map[string]int64{
		"256Mi": 256 * (1 << 20),
		"1Gi":   1 << 30,
		"512M":  512 * 1e6,
		"1000":  1000,
	}
	for in, want := range cases {
		got, err := parseQuantity(in)
		if err != nil || got != want {
			t.Errorf("parseQuantity(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	if _, err := parseQuantity("notanumber"); err == nil {
		t.Errorf("expected error on garbage quantity")
	}
}

func TestParseUnknownJSONIsQuiet(t *testing.T) {
	ws, err := Parse([]byte(`{"hello": "world"}`))
	if err != nil {
		t.Fatalf("unknown JSON should not error, got %v", err)
	}
	if ws != nil {
		t.Errorf("unknown JSON should yield no workloads, got %v", ws)
	}
}

func TestParseGarbageErrors(t *testing.T) {
	if _, err := Parse([]byte("{not json")); err == nil {
		t.Errorf("malformed JSON should error")
	}
}
