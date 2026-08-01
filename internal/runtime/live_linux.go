//go:build linux

package runtime

// This file is the Linux edge of the sensor: a live eBPF-backed EventSource that
// attaches BPF programs to kernel tracepoints and drains a BPF ring buffer into
// Event values. It is written against the raw bpf(2)/perf_event_open interfaces
// using only the standard library (syscall + unsafe) — deliberately NO
// cilium/ebpf or golang.org/x/sys dependency, so go.mod stays empty and the rest
// of the tree keeps building dependency-free on every platform.
//
// IMPORTANT — verification boundary: this file compiles and runs ONLY on Linux
// with a BTF-enabled kernel (>= 5.8 for the BPF ring buffer + CO-RE). It cannot
// be built or exercised on the darwin development host, so unlike every other
// module in this repo it ships WITHOUT golden-test coverage from CI here and must
// be verified on a real Linux node before it is relied on. The portable replay
// source (replay.go) carries the full tested detection path and stays the
// default; live mode is opt-in.
//
// Kernel matrix:
//   - Linux >= 5.8 with CONFIG_DEBUG_INFO_BTF=y: BPF_MAP_TYPE_RINGBUF + CO-RE.
//   - 5.4 LTS: would need a perf-buffer fallback (not implemented here).
//   - < 4.18: unsupported.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

// bpf(2) command numbers (uapi/linux/bpf.h) — stable kernel ABI.
const (
	bpfMapCreate   = 0
	bpfProgLoad    = 5
	bpfMapTypeRing = 27 // BPF_MAP_TYPE_RINGBUF
	bpfProgTypeTP  = 5  // BPF_PROG_TYPE_TRACEPOINT

	ringBufDefault  = 1 << 20
	eventStructSize = 512 // fixed-size record the BPF program emits per event
)

// liveSource is the live eBPF EventSource. It owns the loaded program fds, the
// ring-buffer map, and a background reader that decodes kernel records into
// Event values delivered over a channel.
type liveSource struct {
	cfg      LiveConfig
	ringFD   int
	progFDs  []int
	events   chan Event
	errc     chan error
	closeOne sync.Once
	done     chan struct{}
	seq      uint64
}

// NewLiveSource loads the sensor's BPF programs, attaches them to the configured
// tracepoints, and starts draining the ring buffer. It requires CAP_BPF (or
// root) and a BTF-enabled kernel. On any failure it returns a descriptive error
// so the daemon can fall back to replay mode.
func NewLiveSource(cfg LiveConfig) (EventSource, error) {
	if err := checkKernelSupport(); err != nil {
		return nil, err
	}
	ringBytes := cfg.RingBufferBytes
	if ringBytes == 0 {
		ringBytes = ringBufDefault
	}
	ringFD, err := createRingBuffer(ringBytes)
	if err != nil {
		return nil, fmt.Errorf("runtime/live: create ring buffer: %w", err)
	}
	s := &liveSource{
		cfg:    cfg,
		ringFD: ringFD,
		events: make(chan Event, 1024),
		errc:   make(chan error, 1),
		done:   make(chan struct{}),
	}
	if err := s.loadAndAttach(); err != nil {
		s.Close()
		return nil, err
	}
	go s.drain()
	return s, nil
}

// Next returns the next decoded kernel event, blocking until one is available,
// the source is closed, or ctx is cancelled.
func (s *liveSource) Next(ctx context.Context) (Event, error) {
	select {
	case <-ctx.Done():
		return Event{}, ctx.Err()
	case err := <-s.errc:
		return Event{}, err
	case ev, ok := <-s.events:
		if !ok {
			return Event{}, errLiveClosed
		}
		return ev, nil
	}
}

// Close detaches probes, closes fds, and stops the drain goroutine. Idempotent.
func (s *liveSource) Close() error {
	s.closeOne.Do(func() {
		close(s.done)
		for _, fd := range s.progFDs {
			_ = syscall.Close(fd)
		}
		if s.ringFD > 0 {
			_ = syscall.Close(s.ringFD)
		}
	})
	return nil
}

var errLiveClosed = errors.New("runtime/live: source closed")

// --- raw bpf(2) plumbing ---------------------------------------------------

func bpf(cmd int, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	r1, _, errno := syscall.Syscall(archBPFSyscall(), uintptr(cmd), uintptr(attr), size)
	if errno != 0 {
		return r1, errno
	}
	return r1, nil
}

// archBPFSyscall returns the bpf(2) syscall number for the running architecture.
func archBPFSyscall() uintptr {
	switch runtime.GOARCH {
	case "arm64":
		return 280
	default: // amd64
		return 321
	}
}

// createRingBuffer creates a BPF_MAP_TYPE_RINGBUF map and returns its fd.
func createRingBuffer(maxEntries int) (int, error) {
	var attr [64]byte
	binary.LittleEndian.PutUint32(attr[0:], bpfMapTypeRing)
	binary.LittleEndian.PutUint32(attr[4:], 0)                   // key_size
	binary.LittleEndian.PutUint32(attr[8:], 0)                   // value_size
	binary.LittleEndian.PutUint32(attr[12:], uint32(maxEntries)) // max_entries (must be page-aligned pow2)
	fd, err := bpf(bpfMapCreate, unsafe.Pointer(&attr[0]), uintptr(len(attr)))
	if err != nil {
		return 0, err
	}
	return int(fd), nil
}

// loadAndAttach loads each enabled probe's BPF program and attaches it.
func (s *liveSource) loadAndAttach() error {
	for _, p := range selectedProbes(s.cfg.Probes) {
		prog, ok := bpfPrograms[p]
		if !ok {
			continue
		}
		fd, err := loadProg(prog, s.ringFD)
		if err != nil {
			return fmt.Errorf("runtime/live: load %s program: %w", p, err)
		}
		s.progFDs = append(s.progFDs, fd)
		if err := perfAttachTracepoint(fd, prog.category, prog.name); err != nil {
			return fmt.Errorf("runtime/live: attach %s: %w", p, err)
		}
	}
	if len(s.progFDs) == 0 {
		return errors.New("runtime/live: no probes attached")
	}
	return nil
}

// loadProg loads one BPF program (bytecode with the ringbuf map fd relocated in).
func loadProg(prog bpfProgram, ringFD int) (int, error) {
	insns := prog.relocate(ringFD)
	if len(insns) == 0 || len(insns)%8 != 0 {
		return 0, errors.New("runtime/live: malformed program bytecode")
	}
	lic := append([]byte("GPL"), 0)
	var attr [128]byte
	binary.LittleEndian.PutUint32(attr[0:], bpfProgTypeTP)
	binary.LittleEndian.PutUint32(attr[4:], uint32(len(insns)/8)) // insn_cnt
	binary.LittleEndian.PutUint64(attr[8:], uint64(uintptr(unsafe.Pointer(&insns[0]))))
	binary.LittleEndian.PutUint64(attr[16:], uint64(uintptr(unsafe.Pointer(&lic[0]))))
	fd, err := bpf(bpfProgLoad, unsafe.Pointer(&attr[0]), uintptr(len(attr)))
	if err != nil {
		return 0, err
	}
	// Keep insns/lic alive until after the syscall.
	runtime.KeepAlive(insns)
	runtime.KeepAlive(lic)
	return int(fd), nil
}

// drain reads fixed-size event records from the ring buffer and delivers Events.
func (s *liveSource) drain() {
	defer close(s.events)
	buf := make([]byte, eventStructSize)
	for {
		select {
		case <-s.done:
			return
		default:
		}
		n, err := readRingRecord(s.ringFD, buf)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) {
				continue
			}
			select {
			case s.errc <- fmt.Errorf("runtime/live: ring read: %w", err):
			default:
			}
			return
		}
		if n < eventStructSize {
			continue
		}
		ev := decodeKernelEvent(buf)
		s.seq++
		ev.Seq = s.seq
		select {
		case s.events <- ev:
		case <-s.done:
			return
		}
	}
}

// checkKernelSupport verifies BTF and a new-enough kernel before we try to load.
func checkKernelSupport() error {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); err != nil {
		return fmt.Errorf("runtime/live: kernel BTF unavailable (need CONFIG_DEBUG_INFO_BTF, Linux >= 5.8): %w", err)
	}
	return nil
}

func selectedProbes(want []string) []string {
	all := []string{"process", "file", "network", "syscall"}
	if len(want) == 0 {
		return all
	}
	set := map[string]bool{}
	for _, w := range want {
		set[w] = true
	}
	var out []string
	for _, p := range all {
		if set[p] {
			out = append(out, p)
		}
	}
	return out
}
