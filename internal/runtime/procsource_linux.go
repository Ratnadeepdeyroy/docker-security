//go:build linux

package runtime

// This file is the Linux edge of the /proc-polling live EventSource: it walks
// the real /proc directory's numeric entries and resolves each process's exe
// symlink. Every other piece of logic (parsing the /proc files, diffing
// snapshots, decoding /proc/net/tcp, and the polling loop itself) lives in the
// untagged procparse.go so it is unit-tested on darwin; this file only wires a
// real filesystem walk into that portable ProcSource.

import (
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// defaultProcPollInterval paces how often /proc is re-scanned for new
// processes. A live eBPF probe would notice an exec immediately; polling
// trades that latency for zero kernel privileges.
const defaultProcPollInterval = 2 * time.Second

// NewProcSource builds a live EventSource that polls /proc for new/changed
// processes and their outbound TCP connections, attributing each to a
// container via resolver. cfg is accepted for symmetry with NewLiveSource and
// future tuning (e.g. deriving the poll interval from it); it does not yet
// change behavior.
func NewProcSource(cfg LiveConfig, resolver *ContainerResolver) (*ProcSource, error) {
	_ = cfg
	return &ProcSource{
		root:     "/proc",
		resolver: resolver,
		interval: defaultProcPollInterval,
		snapshot: snapshotProcTable,
	}, nil
}

// snapshotProcTable walks /proc's numeric (pid) entries and parses each one
// via readProcess, overriding Exe with the real exe symlink target when it can
// be read. Processes that disappear or cannot be read mid-scan are skipped
// rather than failing the whole snapshot — that's an ordinary race with a live
// process table, not an error.
func snapshotProcTable() (map[int]ProcessInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	table := make(map[int]ProcessInfo)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		pi, _, err := readProcess("/proc", pid)
		if err != nil {
			continue // process likely exited between readdir and read
		}
		if target, err := os.Readlink(filepath.Join("/proc", e.Name(), "exe")); err == nil {
			pi.Exe = target
		}
		table[pid] = pi
	}
	return table, nil
}
