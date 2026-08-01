//go:build linux

package runtime

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// perfAttachTracepoint attaches a loaded BPF program fd to a kernel tracepoint.
// It resolves the tracepoint's numeric id from tracefs, opens a perf event for
// that tracepoint with perf_event_open(2), then wires the program to it with the
// PERF_EVENT_IOC_SET_BPF ioctl and enables it. All via raw syscalls — no
// dependency.
func perfAttachTracepoint(progFD int, category, name string) error {
	id, err := tracepointID(category, name)
	if err != nil {
		return err
	}
	efd, err := perfEventOpenTracepoint(id)
	if err != nil {
		return fmt.Errorf("perf_event_open %s:%s: %w", category, name, err)
	}
	// PERF_EVENT_IOC_SET_BPF = _IOW('$', 8, __u32) = 0x40042408.
	if err := ioctlSetInt(efd, 0x40042408, progFD); err != nil {
		syscall.Close(efd)
		return fmt.Errorf("PERF_EVENT_IOC_SET_BPF: %w", err)
	}
	// PERF_EVENT_IOC_ENABLE = _IO('$', 0) = 0x2400.
	if err := ioctlSetInt(efd, 0x2400, 0); err != nil {
		syscall.Close(efd)
		return fmt.Errorf("PERF_EVENT_IOC_ENABLE: %w", err)
	}
	return nil
}

// tracepointID reads the numeric tracepoint id from tracefs.
func tracepointID(category, name string) (uint64, error) {
	for _, base := range []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"} {
		p := base + "/events/" + category + "/" + name + "/id"
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		return strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	}
	return 0, fmt.Errorf("tracepoint %s:%s not found in tracefs", category, name)
}

// perfEventAttr mirrors the kernel struct prefix we need for a tracepoint event.
// Only the fields we set matter; the rest stay zero.
type perfEventAttr struct {
	Type       uint32
	Size       uint32
	Config     uint64
	SamplePeri uint64
	SampleType uint64
	ReadFormat uint64
	Flags      uint64
	Wakeup     uint32
	_          uint32
	_          [80]byte // pad to the current struct size; kernel tolerates larger Size
}

const perfTypeTracepoint = 2

// perfEventOpenTracepoint opens a perf event bound to a tracepoint id, on the
// calling process (pid=-1 means all, but we use pid=0/cpu=-1 for this task).
func perfEventOpenTracepoint(id uint64) (int, error) {
	attr := perfEventAttr{
		Type:   perfTypeTracepoint,
		Size:   uint32(unsafe.Sizeof(perfEventAttr{})),
		Config: id,
	}
	// perf_event_open(attr, pid=-1, cpu=0, group_fd=-1, flags=PERF_FLAG_FD_CLOEXEC)
	const sysPerfEventOpen = 298 // amd64; arm64 differs (241)
	nr := uintptr(sysPerfEventOpen)
	if archIsARM64() {
		nr = 241
	}
	r1, _, errno := syscall.Syscall6(nr,
		uintptr(unsafe.Pointer(&attr)),
		^uintptr(0), // pid = -1 (all processes)
		0,           // cpu = 0
		^uintptr(0), // group_fd = -1
		1<<3,        // PERF_FLAG_FD_CLOEXEC
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return int(r1), nil
}

func ioctlSetInt(fd int, req uintptr, arg int) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

func archIsARM64() bool {
	// runtime.GOARCH is set at compile time; use it directly.
	return goArchARM64
}

// --- BPF ring buffer read --------------------------------------------------
//
// The BPF ring buffer is consumed via its mmap'd data pages. A full consumer
// tracks the producer/consumer positions in the ring's header pages. For the
// fixed-size records this sensor emits, we mmap the ring once and read records
// sequentially, advancing the consumer position. readRingRecord copies the next
// record's payload into buf and returns its length, or EAGAIN when empty.

var ringState = struct {
	fd       int
	data     []byte
	consumer *uint64
	dataOff  int
	mask     uint64
}{}

// readRingRecord reads one record from the ring buffer into buf. It lazily mmaps
// the ring on first use. It returns syscall.EAGAIN when no record is ready.
func readRingRecord(fd int, buf []byte) (int, error) {
	if ringState.fd != fd {
		if err := mmapRing(fd); err != nil {
			return 0, err
		}
	}
	// BPF ringbuf record header: len (u32, high bits are flags) + pad (u32).
	prod := ringProducerPos()
	cons := *ringState.consumer
	if cons >= prod {
		return 0, syscall.EAGAIN
	}
	off := ringState.dataOff + int(cons&ringState.mask)
	if off+8 > len(ringState.data) {
		return 0, syscall.EAGAIN
	}
	hdr := binary.LittleEndian.Uint32(ringState.data[off:])
	const busyBit = 1 << 31
	const discardBit = 1 << 30
	if hdr&busyBit != 0 {
		return 0, syscall.EAGAIN // record still being written
	}
	recLen := int(hdr &^ (busyBit | discardBit))
	roundLen := (recLen + 7) / 8 * 8
	*ringState.consumer = cons + uint64(8+roundLen)
	if hdr&discardBit != 0 {
		return 0, syscall.EAGAIN // discarded record; skip
	}
	payloadOff := off + 8
	n := recLen
	if n > len(buf) {
		n = len(buf)
	}
	if payloadOff+n > len(ringState.data) {
		return 0, syscall.EAGAIN
	}
	copy(buf[:n], ringState.data[payloadOff:payloadOff+n])
	return n, nil
}

// mmapRing maps the ring buffer's consumer page and data pages.
func mmapRing(fd int) error {
	pageSize := os.Getpagesize()
	// Consumer position lives in the first page; producer position + data follow.
	consumer, err := syscall.Mmap(fd, 0, pageSize, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("mmap ring consumer page: %w", err)
	}
	// The data region is mapped after the producer page; size is the ring size,
	// double-mapped by the kernel so wrap-around is contiguous.
	dataMap, err := syscall.Mmap(fd, int64(pageSize), pageSize+ringBufDefault*2, syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("mmap ring data pages: %w", err)
	}
	ringState.fd = fd
	ringState.consumer = (*uint64)(unsafe.Pointer(&consumer[0]))
	ringState.data = dataMap
	ringState.dataOff = pageSize // data starts one page past the producer page
	ringState.mask = uint64(ringBufDefault - 1)
	return nil
}

// ringProducerPos reads the producer position from the producer page (the page
// between the consumer page and the data region).
func ringProducerPos() uint64 {
	// Producer position is the first u64 of the data map's first page.
	if len(ringState.data) < 8 {
		return 0
	}
	return *(*uint64)(unsafe.Pointer(&ringState.data[0]))
}
