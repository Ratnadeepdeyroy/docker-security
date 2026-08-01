// sensor.bpf.c — CO-RE eBPF sensor: process, file, network, and syscall events
// plus in-kernel enforcement. Attaches to tracepoints only (no vmlinux.h), so it
// compiles with just libbpf's bpf_helpers.h and loads on any BTF kernel (>=5.8).
//
// All programs emit one fixed-layout `struct event` into a shared ring buffer;
// the `kind` field discriminates. Enforcement: when userspace sets enforce_cfg
// to 1 (armed enforce mode), a shell execing inside a container is SIGKILL'd
// in-kernel via bpf_send_signal before it runs, and the event is flagged killed.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define SIGKILL 9

// open() flag bits we treat as write intent (uapi values, stable across arches).
#define F_WRONLY 00000001
#define F_RDWR   00000002
#define F_CREAT  00000100

enum ev_kind {
	EV_EXEC    = 1,
	EV_FILE    = 2,
	EV_CONNECT = 3,
	EV_SYSCALL = 4,
};

// event MUST match sensorEvent in ebpf_linux.go byte-for-byte (little-endian).
struct event {
	__u32 kind;
	__u32 pid;
	__u32 ppid;   // not resolved without task_struct CO-RE; 0 for now.
	__u32 flags;  // file: open flags
	__u64 cgroup_id;
	__u32 daddr;  // connect: IPv4 dest (network byte order)
	__u16 dport;  // connect: dest port (network byte order)
	__u8  af;     // connect: address family
	__u8  killed; // enforcement: set when this exec was SIGKILL'd in-kernel
	char  comm[16];
	char  str[128]; // exec: filename, file: path, syscall: name
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// enforce_cfg[0] != 0 arms in-kernel shell-kill (set by userspace in armed
// enforce mode). Kept a map, not a constant, so posture flips without reload.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} enforce_cfg SEC(".maps");

static __always_inline void fill_common(struct event *e, __u32 kind)
{
	e->kind = kind;
	__u64 id = bpf_get_current_pid_tgid();
	e->pid = (__u32)(id >> 32);
	e->ppid = 0;
	e->flags = 0;
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->daddr = 0;
	e->dport = 0;
	e->af = 0;
	e->killed = 0;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->str[0] = 0;
}

// is_shell_path returns 1 when the basename of a NUL-terminated path is a known
// shell. Bounded loops keep the verifier happy.
static __always_inline int is_shell_path(const char *f)
{
	int start = 0, len = 0;
#pragma unroll
	for (int i = 0; i < 128; i++) {
		char c = f[i];
		if (c == 0) { len = i; break; }
		if (c == '/') start = i + 1;
	}
	const char *b = f + start;
	int n = len - start;
	if (n == 2 && b[0] == 's' && b[1] == 'h') return 1;                       // sh
	if (n == 3 && b[0] == 'a' && b[1] == 's' && b[2] == 'h') return 1;        // ash
	if (n == 3 && b[0] == 'z' && b[1] == 's' && b[2] == 'h') return 1;        // zsh
	if (n == 4 && b[0] == 'b' && b[1] == 'a' && b[2] == 's' && b[3] == 'h') return 1; // bash
	if (n == 4 && b[0] == 'd' && b[1] == 'a' && b[2] == 's' && b[3] == 'h') return 1; // dash
	return 0;
}

// --- exec (process) ---------------------------------------------------------

struct exec_args {
	__u64 _common;
	__u32 __data_loc_filename; // offset 8
	__s32 pid;
	__s32 old_pid;
};

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct exec_args *ctx)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	fill_common(e, EV_EXEC);
	__u16 off = (__u16)(ctx->__data_loc_filename & 0xFFFF);
	bpf_probe_read_kernel_str(&e->str, sizeof(e->str), (void *)ctx + off);

	// In-kernel enforcement: kill a shell execing inside a container.
	__u32 k = 0;
	__u32 *cfg = bpf_map_lookup_elem(&enforce_cfg, &k);
	if (cfg && *cfg && e->cgroup_id != 0 && is_shell_path(e->str)) {
		bpf_send_signal(SIGKILL);
		e->killed = 1;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// --- file (openat) ----------------------------------------------------------

struct openat_args {
	__u64 _common;
	__s32 __syscall_nr; __u32 _pad;
	__u64 dfd;
	__u64 filename_ptr; // const char __user *
	__u64 flags;
	__u64 mode;
};

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct openat_args *ctx)
{
	// Emit only write-intent opens: reduces ring-buffer volume massively and
	// covers the FIM/persistence/tamper rules (all keyed on writes). Sensitive
	// *read* detection is a documented follow-up.
	__u32 fl = (__u32)ctx->flags;
	if (!(fl & (F_WRONLY | F_RDWR | F_CREAT)))
		return 0;
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	fill_common(e, EV_FILE);
	e->flags = fl;
	bpf_probe_read_user_str(&e->str, sizeof(e->str), (void *)ctx->filename_ptr);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// --- network (connect) ------------------------------------------------------

struct connect_args {
	__u64 _common;
	__s32 __syscall_nr; __u32 _pad;
	__u64 fd;
	__u64 uservaddr; // struct sockaddr __user *
	__u64 addrlen;
};

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct connect_args *ctx)
{
	__u16 fam = 0;
	bpf_probe_read_user(&fam, sizeof(fam), (void *)ctx->uservaddr);
	if (fam != 2) // AF_INET only (v6 is a follow-up)
		return 0;
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	fill_common(e, EV_CONNECT);
	e->af = 2;
	// struct sockaddr_in: family(2) port(2, BE) addr(4, BE)
	bpf_probe_read_user(&e->dport, sizeof(e->dport), (void *)(ctx->uservaddr + 2));
	bpf_probe_read_user(&e->daddr, sizeof(e->daddr), (void *)(ctx->uservaddr + 4));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// --- syscalls of interest ---------------------------------------------------

static __always_inline int emit_syscall(const char *name)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	fill_common(e, EV_SYSCALL);
	bpf_probe_read_kernel_str(&e->str, sizeof(e->str), name);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int on_finit_module(void *ctx) { return emit_syscall("finit_module"); }

SEC("tracepoint/syscalls/sys_enter_init_module")
int on_init_module(void *ctx) { return emit_syscall("init_module"); }

SEC("tracepoint/syscalls/sys_enter_bpf")
int on_bpf(void *ctx) { return emit_syscall("bpf"); }

SEC("tracepoint/syscalls/sys_enter_setns")
int on_setns(void *ctx) { return emit_syscall("setns"); }

SEC("tracepoint/syscalls/sys_enter_mount")
int on_mount(void *ctx) { return emit_syscall("mount"); }

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int on_memfd_create(void *ctx) { return emit_syscall("memfd_create"); }
