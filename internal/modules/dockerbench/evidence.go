// Package dockerbench assesses a Docker host and daemon against the CIS Docker
// Benchmark (CAPABILITY_SPEC domain 10). It is a read-only auditor: it never
// mutates the host. Assessment runs against *collected evidence* — a snapshot of
// the daemon configuration, relevant file permissions, and per-container runtime
// settings — so a scan is deterministic and works fully offline. On a live host
// the collector reads the same inputs (daemon.json, `docker info`, file stats,
// `docker inspect`); in CI or tests the identical evidence document is committed
// as a fixture.
package dockerbench

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// maxEvidenceBytes bounds how much we will read from an evidence document, so a
// hostile or corrupt file cannot exhaust memory. 16 MiB is far more than any
// real daemon.json + inspect snapshot.
const maxEvidenceBytes = 16 << 20

// Evidence is the offline-assessable snapshot of a Docker host. Every field is
// optional; a missing field degrades the affected controls to INFO/unknown
// rather than failing the run.
type Evidence struct {
	// Daemon is the parsed daemon.json (raw, so new keys need no code change).
	Daemon map[string]any `json:"daemon,omitempty"`
	// Info is the subset of `docker info` that reflects effective daemon state.
	Info Info `json:"info,omitempty"`
	// Files are permission/ownership stats for security-relevant paths.
	Files []FileStat `json:"files,omitempty"`
	// Containers is the runtime config of running containers.
	Containers []Container `json:"containers,omitempty"`
	// Notes records collection gaps (e.g. "daemon.json unreadable"), surfaced
	// to the operator without failing the scan.
	Notes []string `json:"notes,omitempty"`
}

// Info mirrors the security-relevant fields of `docker info`. Effective values
// here take precedence when a daemon.json key is absent (a flag or default may
// still have set it).
type Info struct {
	ServerVersion string   `json:"server_version,omitempty"`
	Rootless      bool     `json:"rootless,omitempty"`
	LiveRestore   bool     `json:"live_restore,omitempty"`
	Experimental  bool     `json:"experimental,omitempty"`
	LoggingDriver string   `json:"logging_driver,omitempty"`
	CgroupDriver  string   `json:"cgroup_driver,omitempty"`
	SecurityOpts  []string `json:"security_options,omitempty"` // e.g. "name=seccomp,profile=builtin"
	StorageDriver string   `json:"storage_driver,omitempty"`
}

// FileStat is a security-relevant path with its ownership and mode.
type FileStat struct {
	Path   string `json:"path"`
	Exists bool   `json:"exists"`
	Mode   string `json:"mode,omitempty"`  // octal, e.g. "0644"
	Owner  string `json:"owner,omitempty"` // username or uid
	Group  string `json:"group,omitempty"` // group name or gid
}

// Container is the runtime configuration of one container (from docker inspect),
// reduced to the fields CIS section 5 cares about.
type Container struct {
	Name            string        `json:"name"`
	Privileged      bool          `json:"privileged,omitempty"`
	CapAdd          []string      `json:"cap_add,omitempty"`
	CapDrop         []string      `json:"cap_drop,omitempty"`
	SecurityOpt     []string      `json:"security_opt,omitempty"`
	PidMode         string        `json:"pid_mode,omitempty"`
	IpcMode         string        `json:"ipc_mode,omitempty"`
	UtsMode         string        `json:"uts_mode,omitempty"`
	NetworkMode     string        `json:"network_mode,omitempty"`
	ReadonlyRootfs  bool          `json:"readonly_rootfs,omitempty"`
	User            string        `json:"user,omitempty"`
	MemoryLimit     int64         `json:"memory_limit,omitempty"`
	PidsLimit       int64         `json:"pids_limit,omitempty"`
	CPUShares       int64         `json:"cpu_shares,omitempty"`
	RestartPolicy   string        `json:"restart_policy,omitempty"`
	RestartMaxRetry int           `json:"restart_max_retry,omitempty"`
	Healthcheck     bool          `json:"healthcheck,omitempty"`
	Mounts          []Mount       `json:"mounts,omitempty"`
	PortBindings    []PortBinding `json:"port_bindings,omitempty"`
}

// Mount is a bind/volume mount, enough to spot sensitive host paths and the
// Docker socket being handed into a container.
type Mount struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	RW          bool   `json:"rw"`
}

// PortBinding is a published port, enough to spot 0.0.0.0 exposure and
// privileged host ports.
type PortBinding struct {
	HostIP        string `json:"host_ip"`
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
}

// Load reads an evidence document for assessment. It accepts either a JSON
// evidence file, or a directory containing `evidence.json` (the collected
// snapshot) — and, failing that, a directory holding a real `daemon.json`,
// which it parses best-effort. A path that does not exist yields an empty
// Evidence with a Note, so the caller degrades to INFO rather than crashing.
func Load(path string) (*Evidence, error) {
	if path == "" {
		return &Evidence{Notes: []string{"no evidence path provided"}}, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return &Evidence{Notes: []string{fmt.Sprintf("evidence path %q not found: %v", path, err)}}, nil
	}

	if !info.IsDir() {
		return loadJSONFile(path)
	}

	// Directory: prefer a consolidated snapshot, then a bare daemon.json.
	if p := filepath.Join(path, "evidence.json"); fileExists(p) {
		return loadJSONFile(p)
	}
	if p := filepath.Join(path, "daemon.json"); fileExists(p) {
		return loadDaemonOnly(p)
	}
	return &Evidence{Notes: []string{fmt.Sprintf("no evidence.json or daemon.json under %q", path)}}, nil
}

// loadJSONFile parses a consolidated Evidence document, bounding the read.
func loadJSONFile(path string) (*Evidence, error) {
	data, err := readCapped(path)
	if err != nil {
		return nil, fmt.Errorf("read evidence %q: %w", path, err)
	}
	var ev Evidence
	if err := json.Unmarshal(data, &ev); err != nil {
		return nil, fmt.Errorf("parse evidence %q: %w", path, err)
	}
	return &ev, nil
}

// loadDaemonOnly parses just a daemon.json into the Daemon map when no
// consolidated snapshot exists — the common "point me at /etc/docker" case.
func loadDaemonOnly(path string) (*Evidence, error) {
	data, err := readCapped(path)
	if err != nil {
		return nil, fmt.Errorf("read daemon.json %q: %w", path, err)
	}
	var daemon map[string]any
	if err := json.Unmarshal(data, &daemon); err != nil {
		return nil, fmt.Errorf("parse daemon.json %q: %w", path, err)
	}
	return &Evidence{
		Daemon: daemon,
		Notes:  []string{"assessed daemon.json only; file-permission and runtime controls need a full evidence snapshot"},
	}, nil
}

// readCapped reads at most maxEvidenceBytes from a file.
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

// --- daemon.json typed accessors -------------------------------------------
//
// daemon.json is untyped JSON, so these total, nil-safe helpers pull typed
// values out for the checks. Each reports presence separately from value, so a
// check can distinguish "explicitly false" from "unset (default applies)".

func (e *Evidence) daemonBool(key string) (val, present bool) {
	if e.Daemon == nil {
		return false, false
	}
	v, ok := e.Daemon[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

func (e *Evidence) daemonString(key string) (string, bool) {
	if e.Daemon == nil {
		return "", false
	}
	v, ok := e.Daemon[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}

func (e *Evidence) daemonStrings(key string) ([]string, bool) {
	if e.Daemon == nil {
		return nil, false
	}
	v, ok := e.Daemon[key]
	if !ok {
		return nil, false
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out, true
}

// daemonPresent reports whether a key exists at all (value-agnostic).
func (e *Evidence) daemonPresent(key string) bool {
	if e.Daemon == nil {
		return false
	}
	_, ok := e.Daemon[key]
	return ok
}

// file returns the stat for a path, and whether it was collected.
func (e *Evidence) file(path string) (FileStat, bool) {
	for _, f := range e.Files {
		if f.Path == path {
			return f, true
		}
	}
	return FileStat{}, false
}

// hasDaemonEvidence reports whether there is anything to assess — used by the
// module to stay quiet on a filesystem scan that isn't a Docker host.
func (e *Evidence) hasDaemonEvidence() bool {
	return e.Daemon != nil || len(e.Files) > 0 || len(e.Containers) > 0 ||
		e.Info.ServerVersion != "" || len(e.Info.SecurityOpts) > 0
}
