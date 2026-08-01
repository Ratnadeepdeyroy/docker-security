//go:build linux

package runtime

import (
	"encoding/binary"
	"net"
)

// decodeKernelEvent converts one fixed-size ring-buffer record into an Event.
// The on-wire layout is the contract between the BPF programs (which fill it in
// kernel space) and this decoder; it is deliberately fixed-size and
// C-struct-compatible so the kernel side is a plain struct write.
//
// Layout (little-endian, total eventStructSize bytes):
//
//	 0  u8   kind        (1=process, 2=file, 3=network, 4=syscall)
//	 1  u8   _pad
//	 2  u16  _pad
//	 4  u32  pid
//	 8  u32  ppid
//	12  u32  uid
//	16  u32  gid
//	20  u64  cgroup_id
//	28  u64  time_ns
//	36  [64]byte comm (NUL-terminated)
//	100 [128]byte exe/path (NUL-terminated; process exe or file path)
//	228 u32  remote_ip (network, IPv4 BE)
//	232 u16  remote_port (network, host order)
//	234 u8   proto (network: 6=tcp,17=udp)
//	235 u8   file_op (file: 1=open,2=write,3=unlink,4=chmod)
//	236 ...  reserved
func decodeKernelEvent(rec []byte) Event {
	if len(rec) < 236 {
		return Event{Kind: KindSyscall}
	}
	kind := rec[0]
	pid := int(binary.LittleEndian.Uint32(rec[4:]))
	ppid := int(binary.LittleEndian.Uint32(rec[8:]))
	uid := int(binary.LittleEndian.Uint32(rec[12:]))
	gid := int(binary.LittleEndian.Uint32(rec[16:]))
	cgroup := binary.LittleEndian.Uint64(rec[20:])
	timeNS := int64(binary.LittleEndian.Uint64(rec[28:]))
	comm := cstr(rec[36:100])
	path := cstr(rec[100:228])

	ev := Event{
		TimeUnixNano: timeNS,
		Process: ProcessInfo{
			PID:      pid,
			PPID:     ppid,
			UID:      uid,
			GID:      gid,
			Comm:     comm,
			CgroupID: cgroup,
		},
		Container: ContainerInfo{},
	}

	switch kind {
	case 1: // process exec
		ev.Kind = KindProcess
		ev.Process.Exe = path
	case 2: // file
		ev.Kind = KindFile
		ev.File = &FileEvent{Path: path, Op: fileOp(rec[235])}
	case 3: // network
		ev.Kind = KindNetwork
		ip := net.IPv4(rec[228], rec[229], rec[230], rec[231]).String()
		ev.Network = &NetworkEvent{
			Op:         "connect",
			Direction:  "egress",
			Proto:      proto(rec[234]),
			RemoteIP:   ip,
			RemotePort: int(binary.LittleEndian.Uint16(rec[232:])),
		}
	default: // syscall
		ev.Kind = KindSyscall
		ev.Process.Exe = path
	}
	return ev
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func fileOp(v byte) string {
	switch v {
	case 1:
		return "open"
	case 2:
		return "write"
	case 3:
		return "unlink"
	case 4:
		return "chmod"
	default:
		return "access"
	}
}

func proto(v byte) string {
	switch v {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return ""
	}
}
