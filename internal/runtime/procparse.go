// Package runtime (this file): a live /proc-polling EventSource.
//
// This file holds every piece of logic that is testable without a real Linux
// kernel: parsing the handful of /proc/<pid> files the sensor cares about,
// diffing successive process-table snapshots into exec events, and decoding
// /proc/<pid>/net/tcp connection rows. None of it touches an actual /proc
// directory — callers pass a root path, so tests substitute a fixture
// directory built with plain files (see procsource_test.go). The only bits
// that require real Linux (walking /proc's numeric entries and reading the
// exe symlink via os.Readlink) live behind the //go:build linux tag in
// procsource_linux.go, which calls into the parser here.
package runtime

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// readProcess reads the /proc-shaped files under root/<pid>/ and returns the
// parsed ProcessInfo plus the raw first non-empty /proc/<pid>/cgroup line (for
// callers that want to attribute the process to a container via
// ContainerResolver.ByCgroup). It returns an error only when the process
// directory or its comm file cannot be read (e.g. the process has exited),
// mirroring how a real /proc walk degrades.
func readProcess(root string, pid int) (ProcessInfo, string, error) {
	dir := filepath.Join(root, strconv.Itoa(pid))

	commBytes, err := os.ReadFile(filepath.Join(dir, "comm"))
	if err != nil {
		return ProcessInfo{}, "", fmt.Errorf("runtime: read comm for pid %d: %w", pid, err)
	}
	pi := ProcessInfo{PID: pid}
	pi.Comm = strings.TrimRight(string(commBytes), "\n")

	if cmdline, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		args := splitNULArgs(string(cmdline))
		pi.Args = args
		if len(args) > 0 {
			pi.Exe = args[0]
		}
	}

	// exe.target is the darwin-testable shim for the real exe symlink; the
	// Linux-tagged source overrides Exe with os.Readlink(root/<pid>/exe) when
	// that succeeds.
	if target, err := os.ReadFile(filepath.Join(dir, "exe.target")); err == nil {
		if t := strings.TrimSpace(string(target)); t != "" {
			pi.Exe = t
		}
	}

	var cgroupLine string
	if cgroup, err := os.ReadFile(filepath.Join(dir, "cgroup")); err == nil {
		for _, line := range strings.Split(string(cgroup), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				cgroupLine = line
				break
			}
		}
	}

	if status, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
		parseStatus(string(status), &pi)
	}

	pi.TTY, pi.StdioSocket = scanFDs(filepath.Join(dir, "fd"))

	return pi, cgroupLine, nil
}

// splitNULArgs splits a raw /proc/<pid>/cmdline blob (NUL-separated argv,
// with a trailing NUL) into its argument strings, dropping any empty trailing
// element produced by that terminator.
func splitNULArgs(raw string) []string {
	raw = strings.TrimSuffix(raw, "\x00")
	if raw == "" {
		return nil
	}
	return strings.Split(raw, "\x00")
}

// parseStatus fills PPID and UID from a /proc/<pid>/status blob. Malformed or
// missing fields are left at their zero value.
func parseStatus(status string, pi *ProcessInfo) {
	for _, line := range strings.Split(status, "\n") {
		switch {
		case strings.HasPrefix(line, "PPid:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if v, err := strconv.Atoi(fields[1]); err == nil {
					pi.PPID = v
				}
			}
		case strings.HasPrefix(line, "Uid:"):
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if v, err := strconv.Atoi(fields[1]); err == nil {
					pi.UID = v
				}
			}
		}
	}
}

// scanFDs best-effort inspects root/<pid>/fd/* entries and reports whether the
// process looks like it has a controlling TTY (any fd pointing at /dev/pts)
// and whether stdio (fd 0/1/2) is bound to a socket — the tell-tale of a
// reverse/bind shell. Entries may be real symlinks (real /proc) or plain files
// whose contents mimic a link target (test fixtures); both are handled.
func scanFDs(fdDir string) (tty bool, stdioSocket bool) {
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return false, false
	}
	for _, e := range entries {
		name := e.Name()
		target := fdTarget(filepath.Join(fdDir, name))
		if target == "" {
			continue
		}
		if strings.Contains(target, "/dev/pts") {
			tty = true
		}
		if (name == "0" || name == "1" || name == "2") && strings.Contains(target, "socket:") {
			stdioSocket = true
		}
	}
	return tty, stdioSocket
}

// fdTarget resolves what a single fd entry points at: a real symlink is read
// with os.Readlink; failing that (a fixture using a plain regular file), the
// file's contents are read and trimmed instead.
func fdTarget(path string) string {
	if target, err := os.Readlink(path); err == nil {
		return target
	}
	if data, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}

// diffProcTable compares two process-table snapshots and returns one
// KindProcess Event for every PID in cur that is either new (absent from
// prev) or has changed its Exe since prev — i.e. an exec was observed. Events
// are ordered by ascending PID for deterministic output; Seq is left zero, the
// caller (ProcSource.Next) assigns it.
func diffProcTable(prev, cur map[int]ProcessInfo) []Event {
	var pids []int
	for pid := range cur {
		old, existed := prev[pid]
		if !existed || old.Exe != cur[pid].Exe {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)

	events := make([]Event, 0, len(pids))
	for _, pid := range pids {
		events = append(events, Event{
			Kind:    KindProcess,
			Process: cur[pid],
		})
	}
	return events
}

// readTCPConnections parses root/<pid>/net/tcp and root/<pid>/net/tcp6 (the
// latter read best-effort, absent on hosts/fixtures without IPv6) into
// NetworkEvent connect records. Only rows in state ESTABLISHED ("01") or
// SYN_SENT ("02") are reported, and rows with an all-zero remote address or
// port 0 are skipped (listening sockets, not outbound connections).
// Malformed lines are tolerated by skipping them rather than failing the
// whole read.
func readTCPConnections(root string, pid int) []NetworkEvent {
	var out []NetworkEvent
	dir := filepath.Join(root, strconv.Itoa(pid), "net")
	out = append(out, parseTCPFile(filepath.Join(dir, "tcp"))...)
	out = append(out, parseTCPFile(filepath.Join(dir, "tcp6"))...)
	return out
}

func parseTCPFile(path string) []NetworkEvent {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []NetworkEvent
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue // header line
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		remoteField := fields[2]
		state := fields[3]
		if state != "01" && state != "02" {
			continue
		}
		ip, port, ok := decodeHexAddr(remoteField)
		if !ok {
			continue
		}
		if port == 0 || ip.IsUnspecified() {
			continue
		}
		out = append(out, NetworkEvent{
			Op:         "connect",
			Proto:      "tcp",
			RemoteIP:   ip.String(),
			RemotePort: port,
			Direction:  "egress",
		})
	}
	return out
}

// decodeHexAddr decodes a "HEXADDR:HEXPORT" field from /proc/net/tcp{,6} — the
// address bytes are little-endian per 32-bit word (IPv4: 4 bytes / 8 hex
// chars, e.g. "0100007F" -> 127.0.0.1; IPv6: 16 bytes / 32 hex chars).
func decodeHexAddr(field string) (net.IP, int, bool) {
	parts := strings.SplitN(field, ":", 2)
	if len(parts) != 2 {
		return nil, 0, false
	}
	addrHex, portHex := parts[0], parts[1]
	port64, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return nil, 0, false
	}
	addrBytes, err := hex.DecodeString(addrHex)
	if err != nil || (len(addrBytes) != 4 && len(addrBytes) != 16) {
		return nil, 0, false
	}

	ip := make(net.IP, len(addrBytes))
	// Each 4-byte (32-bit) word is stored little-endian.
	for word := 0; word+4 <= len(addrBytes); word += 4 {
		ip[word+0] = addrBytes[word+3]
		ip[word+1] = addrBytes[word+2]
		ip[word+2] = addrBytes[word+1]
		ip[word+3] = addrBytes[word+0]
	}
	return ip, int(port64), true
}

// --- ProcSource: a /proc-polling EventSource ------------------------------

// ProcSource is a live EventSource that polls a process table snapshot
// function on an interval and turns the diffs into KindProcess (and
// associated network) events. The parsing/diff logic above is what makes this
// portable to test: snapshot is injected, so ProcSource itself never touches
// a real filesystem in tests. The real Linux constructor (NewProcSource in
// procsource_linux.go) wires snapshot to an actual /proc walk.
type ProcSource struct {
	root     string
	resolver *ContainerResolver
	interval time.Duration
	snapshot func() (map[int]ProcessInfo, error)

	prev    map[int]ProcessInfo
	queue   []Event
	seq     uint64
	started bool
}

// Next returns the next event. On each call it first drains any events queued
// from a previous poll; when the queue is empty it polls again: wait for the
// interval (or proceed immediately if interval is zero), take a snapshot, diff
// it against the previous one, and enqueue an event per changed PID (with a
// best-effort container attribution and any newly observed TCP connections for
// that PID appended).
//
// Documented test-only behavior: to keep the polling loop from spinning
// forever when a caller injects a snapshot function that has reached a fixed
// point (two consecutive identical snapshots) after the first snapshot was
// already taken, Next returns io.EOF rather than looping indefinitely. A real
// /proc poll never reaches this path in practice since interval > 0 paces it,
// but it is what lets a deterministic, interval-0 unit test terminate instead
// of looping forever waiting for a process-table change that will never come.
func (s *ProcSource) Next(ctx context.Context) (Event, error) {
	for {
		if len(s.queue) > 0 {
			ev := s.queue[0]
			s.queue = s.queue[1:]
			return ev, nil
		}

		select {
		case <-ctx.Done():
			return Event{}, ctx.Err()
		default:
		}

		if s.interval > 0 {
			timer := time.NewTimer(s.interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return Event{}, ctx.Err()
			case <-timer.C:
			}
		}

		cur, err := s.snapshot()
		if err != nil {
			return Event{}, err
		}

		wasStarted := s.started
		prev := s.prev
		s.prev = cur
		s.started = true

		// Container attribution is best-effort and optional: readProcess
		// returns the raw cgroup line, but diffProcTable's map[int]ProcessInfo
		// snapshots do not carry it through to this loop, so a resolver is
		// only useful once a future snapshot shape threads the cgroup line
		// alongside each ProcessInfo. Until then, attribution is skipped here
		// even when s.resolver is non-nil.
		evs := diffProcTable(prev, cur)
		for _, ev := range evs {
			s.queue = append(s.queue, ev)
			if s.root != "" {
				for _, nEv := range readTCPConnections(s.root, ev.Process.PID) {
					nEv := nEv
					s.queue = append(s.queue, Event{Kind: KindNetwork, Process: ev.Process, Network: &nEv})
				}
			}
		}

		for i := range s.queue {
			s.seq++
			s.queue[i].Seq = s.seq
		}

		if len(s.queue) > 0 {
			ev := s.queue[0]
			s.queue = s.queue[1:]
			return ev, nil
		}

		// Only the interval-0 unit-test path terminates on a steady state: a
		// real live sensor (interval > 0) must keep polling across idle windows
		// where no process execs, so it never returns EOF here — that would make
		// the daemon treat a quiet node as end-of-stream and exit.
		if s.interval == 0 && wasStarted && sameProcTable(prev, cur) {
			return Event{}, io.EOF
		}
	}
}

// sameProcTable reports whether two process-table snapshots are identical in
// the sense diffProcTable cares about (same PID set, same Exe per PID).
func sameProcTable(a, b map[int]ProcessInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for pid, pa := range a {
		pb, ok := b[pid]
		if !ok || pa.Exe != pb.Exe {
			return false
		}
	}
	return true
}

// Close releases resources held by ProcSource. Polling holds no open
// descriptors between calls, so this is a no-op.
func (s *ProcSource) Close() error { return nil }
