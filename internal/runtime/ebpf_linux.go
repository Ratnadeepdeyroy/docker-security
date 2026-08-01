//go:build linux

package runtime

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -go-package runtime -output-dir . -cflags "-O2 -g -Wall -I/usr/include/aarch64-linux-gnu" sensor ./bpf/sensor.bpf.c

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// This file is the real eBPF sensor. It loads the multi-program object built by
// bpf2go from bpf/sensor.bpf.c and attaches tracepoints for process exec, file
// opens (write-intent), network connects, and the syscalls the kernel-abuse /
// escape / fileless rules care about — feeding them into the same Event pipeline
// the /proc source and replay use. Its advantages over the /proc source:
//   - gap-free: the kernel fires on every event, so short-lived processes and
//     file/syscall activity a poller misses are captured.
//   - container attribution: each event carries the cgroup id, resolved here to
//     container metadata (image/name) via the runtime CLI.
//   - in-kernel enforcement: in armed enforce mode a shell execing inside a
//     container is SIGKILL'd before it runs (bpf_send_signal), not after.
//
// Linux-only; depends on github.com/cilium/ebpf. The non-Linux build
// (ebpf_other.go) returns ErrLiveUnsupported so the scanner never pulls the dep.

const (
	evExec    = 1
	evFile    = 2
	evConnect = 3
	evSyscall = 4
)

// sensorEvent mirrors `struct event` in bpf/sensor.bpf.c byte-for-byte (LE).
type sensorEvent struct {
	Kind     uint32
	PID      uint32
	PPID     uint32
	Flags    uint32
	CgroupID uint64
	Daddr    uint32
	Dport    uint16
	Af       uint8
	Killed   uint8
	Comm     [16]byte
	Str      [128]byte
}

// ebpfSource implements EventSource over a ring buffer fed by the kernel probes.
type ebpfSource struct {
	objs   sensorObjects
	links  []link.Link
	reader *ringbuf.Reader
	cgroup *cgroupAttributor
	ch     chan Event
	errc   chan error
	seq    uint64
	cancel context.CancelFunc
}

// NewEBPFSource loads the sensor object, attaches every probe, and returns a live
// EventSource. It needs a BTF-capable kernel (checked by the caller), CAP_BPF /
// root, and tracefs mounted for tracepoint attach.
func NewEBPFSource(cfg LiveConfig, resolver *ContainerResolver) (EventSource, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("ebpf: remove memlock rlimit: %w", err)
	}
	var objs sensorObjects
	if err := loadSensorObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("ebpf: load objects: %w", err)
	}

	// (tracepoint category, name, program) for every probe.
	probes := []struct {
		cat, name string
		prog      *ebpf.Program
	}{
		{"sched", "sched_process_exec", objs.HandleExec},
		{"syscalls", "sys_enter_openat", objs.HandleOpenat},
		{"syscalls", "sys_enter_connect", objs.HandleConnect},
		{"syscalls", "sys_enter_finit_module", objs.OnFinitModule},
		{"syscalls", "sys_enter_init_module", objs.OnInitModule},
		{"syscalls", "sys_enter_bpf", objs.OnBpf},
		{"syscalls", "sys_enter_setns", objs.OnSetns},
		{"syscalls", "sys_enter_mount", objs.OnMount},
		{"syscalls", "sys_enter_memfd_create", objs.OnMemfdCreate},
	}
	var links []link.Link
	for _, p := range probes {
		l, err := link.Tracepoint(p.cat, p.name, p.prog, nil)
		if err != nil {
			for _, done := range links {
				done.Close()
			}
			objs.Close()
			return nil, fmt.Errorf("ebpf: attach %s/%s: %w", p.cat, p.name, err)
		}
		links = append(links, l)
	}

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		objs.Close()
		return nil, fmt.Errorf("ebpf: open ring buffer: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &ebpfSource{
		objs:   objs,
		links:  links,
		reader: reader,
		cgroup: &cgroupAttributor{resolver: resolver, cache: map[uint64]ContainerInfo{}},
		ch:     make(chan Event, 512),
		errc:   make(chan error, 1),
		cancel: cancel,
	}
	go s.pump(ctx)
	return s, nil
}

// ArmShellKill flips the in-kernel enforcement toggle on: a shell execing inside
// a container is SIGKILL'd by the probe. Called by the daemon only in armed
// enforce mode. Satisfies the ShellKillEnforcer interface.
func (s *ebpfSource) ArmShellKill() error {
	var key, val uint32 = 0, 1
	if err := s.objs.EnforceCfg.Update(&key, &val, 0); err != nil {
		return fmt.Errorf("ebpf: arm enforcement: %w", err)
	}
	return nil
}

func (s *ebpfSource) pump(ctx context.Context) {
	for {
		rec, err := s.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return
			}
			select {
			case s.errc <- err:
			default:
			}
			return
		}
		var raw sensorEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}
		ev, ok := decodeSensorEvent(&raw)
		if !ok {
			continue
		}
		s.seq++
		ev.Seq = s.seq
		if ci, ok := s.cgroup.lookup(raw.CgroupID); ok {
			ev.Container = ci
		}
		if raw.Killed != 0 {
			if ev.Labels == nil {
				ev.Labels = map[string]string{}
			}
			ev.Labels["enforced"] = "kernel-sigkill"
		}
		select {
		case s.ch <- ev:
		case <-ctx.Done():
			return
		}
	}
}

// decodeSensorEvent turns one kernel record into an Event. Returns false for a
// kind it does not model.
func decodeSensorEvent(raw *sensorEvent) (Event, bool) {
	proc := ProcessInfo{PID: int(raw.PID), PPID: int(raw.PPID), Comm: cString(raw.Comm[:])}
	switch raw.Kind {
	case evExec:
		proc.Exe = cString(raw.Str[:])
		return Event{Kind: KindProcess, Process: proc}, true
	case evFile:
		return Event{Kind: KindFile, Process: proc, File: &FileEvent{
			Path:  cString(raw.Str[:]),
			Op:    "write", // only write-intent opens are emitted by the probe
			Flags: openFlagsString(raw.Flags),
		}}, true
	case evConnect:
		return Event{Kind: KindNetwork, Process: proc, Network: &NetworkEvent{
			Op:         "connect",
			Proto:      "tcp",
			RemoteIP:   ipv4String(raw.Daddr),
			RemotePort: int(ntohs(raw.Dport)),
			Direction:  "egress",
		}}, true
	case evSyscall:
		return Event{Kind: KindSyscall, Process: proc, Syscall: &SyscallEvent{Name: cString(raw.Str[:])}}, true
	}
	return Event{}, false
}

func (s *ebpfSource) Next(ctx context.Context) (Event, error) {
	select {
	case <-ctx.Done():
		return Event{}, ctx.Err()
	case err := <-s.errc:
		return Event{}, err
	case ev := <-s.ch:
		return ev, nil
	}
}

func (s *ebpfSource) Close() error {
	s.cancel()
	if s.reader != nil {
		s.reader.Close()
	}
	for _, l := range s.links {
		l.Close()
	}
	s.objs.Close()
	return nil
}

// --- helpers ---------------------------------------------------------------

// cgroupAttributor resolves a kernel cgroup id (cgroup-v2 dir inode) to container
// metadata, by finding the matching cgroupfs directory and running it through the
// runtime-CLI resolver. Results (including misses) are cached per cgroup id.
type cgroupAttributor struct {
	resolver *ContainerResolver
	mu       sync.Mutex
	cache    map[uint64]ContainerInfo
}

func (c *cgroupAttributor) lookup(id uint64) (ContainerInfo, bool) {
	if id == 0 || c.resolver == nil {
		return ContainerInfo{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ci, ok := c.cache[id]; ok {
		return ci, ci.ID != "" || ci.Name != ""
	}
	path := findCgroupPathByInode(id)
	var ci ContainerInfo
	if path != "" {
		ci, _ = c.resolver.ByCgroup(path)
	}
	c.cache[id] = ci
	return ci, ci.ID != "" || ci.Name != ""
}

// findCgroupPathByInode walks cgroup-v2 fs for the directory whose inode matches
// id (== the kernel cgroup id). Returns "" if none. Called only on cache miss.
func findCgroupPathByInode(id uint64) string {
	root := "/sys/fs/cgroup"
	var found string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		info, err := os.Stat(p)
		if err != nil {
			return nil
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Ino == id {
			found = p
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func ipv4String(be uint32) string {
	// be holds the 4 sockaddr bytes in original (network) order in bits 0..31
	// because it was read little-endian, so low byte = first octet.
	return fmt.Sprintf("%d.%d.%d.%d", be&0xff, (be>>8)&0xff, (be>>16)&0xff, (be>>24)&0xff)
}

func ntohs(be uint16) uint16 { return be<<8 | be>>8 }

func openFlagsString(fl uint32) string {
	var parts []string
	if fl&0x1 != 0 {
		parts = append(parts, "O_WRONLY")
	}
	if fl&0x2 != 0 {
		parts = append(parts, "O_RDWR")
	}
	if fl&0x40 != 0 {
		parts = append(parts, "O_CREAT")
	}
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += "|" + p
	}
	return out
}
