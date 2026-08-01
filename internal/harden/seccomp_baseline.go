package harden

// --- Least-privilege seccomp generation --------------------------------------
//
// A seccomp profile generated purely from observed syscalls has a bootstrapping
// problem: if the trace missed a syscall the C runtime issues before main() (or
// during a clean exit), enforcing the profile kills the process for reasons that
// have nothing to do with its actual work. So the generator always unions the
// observed set with a small, curated "process bootstrap minimum" — the calls any
// dynamically-linked Linux process needs to start, manage its own memory and
// signals, and exit. This is our own conservative list, not a copy of Docker's
// ~350-entry default allow-list; the whole point of profile-from-behaviour is to
// allow far less than the default profile does.

// bootstrapSyscalls is the minimum set required for a glibc/musl process to
// initialise, handle signals, allocate memory, and exit cleanly. Everything else
// must be earned by observation. Kept sorted for readability; the generator
// re-sorts the final union regardless.
var bootstrapSyscalls = []string{
	"arch_prctl",        // TLS setup on amd64
	"brk",               // heap
	"clock_getres",      // time
	"clock_gettime",     // time / monotonic
	"clock_nanosleep",   // sleeps
	"close",             // fd lifecycle
	"close_range",       // fd lifecycle (modern)
	"exit",              // thread exit
	"exit_group",        // process exit
	"fstat",             // runtime linker / stdio
	"futex",             // pthread synchronisation
	"getpid",            // common libc bookkeeping
	"getrandom",         // stack canary / ASLR seeding
	"gettid",            // threading
	"madvise",           // allocator hints
	"mmap",              // map libraries / arenas
	"mprotect",          // relro, guard pages
	"munmap",            // free arenas
	"nanosleep",         // sleeps
	"prlimit64",         // libc reads its own rlimits
	"read",              // stdio
	"restart_syscall",   // kernel re-entry after signal
	"rseq",              // restartable sequences (modern glibc)
	"rt_sigaction",      // signal handlers
	"rt_sigprocmask",    // signal masking
	"rt_sigreturn",      // signal return trampoline
	"sched_getaffinity", // runtime sizing
	"sched_yield",       // spin-wait backoff
	"set_robust_list",   // pthread cleanup
	"set_tid_address",   // thread teardown
	"sigaltstack",       // alternate signal stack
	"tgkill",            // pthread_kill / abort
	"write",             // stdio / stderr
}

// defaultArchitectures covers the two architectures this project realistically
// runs on (amd64, arm64) plus their compat sub-architectures, matching how the
// Docker default profile lists them. A caller can override via SeccompOptions.
var defaultArchitectures = []string{
	"SCMP_ARCH_X86_64",
	"SCMP_ARCH_X86",
	"SCMP_ARCH_X32",
	"SCMP_ARCH_AARCH64",
	"SCMP_ARCH_ARM",
}

// SeccompOptions tunes profile generation. The zero value is a sane enforcing
// profile named "dsecrat-generated" for the default architectures.
type SeccompOptions struct {
	// Name labels the profile (currently informational; the JSON schema has no
	// name field, but callers use it for the output filename).
	Name string
	// Architectures overrides defaultArchitectures when non-empty.
	Architectures []string
	// AuditMode makes the default action ActLog instead of ActErrno: the profile
	// allows everything but logs anything outside the observed set, so an operator
	// can widen the observation before switching to enforce. This is the safe
	// first half of the profile-from-behaviour loop.
	AuditMode bool
	// ErrnoRet is the errno a denied syscall returns in enforce mode (default 1,
	// EPERM). 38 (ENOSYS) is common when hiding a syscall's existence.
	ErrnoRet uint
}

// GenerateSeccomp builds a least-privilege seccomp profile from an observation.
// The allow-set is the observed syscalls unioned with the bootstrap minimum; the
// default action denies (or, in audit mode, logs) everything else. Given the
// same observation and options the output is byte-identical — the allow-set is
// sorted and deduplicated.
func GenerateSeccomp(obs Observation, opts SeccompOptions) *SeccompProfile {
	arch := opts.Architectures
	if len(arch) == 0 {
		arch = defaultArchitectures
	}

	allowed := dedupeSort(append(append([]string{}, bootstrapSyscalls...), obs.syscallSet()...))

	p := &SeccompProfile{
		Architectures: append([]string(nil), arch...),
		Syscalls: []SeccompRule{
			{Names: allowed, Action: ActAllow},
		},
	}
	if opts.AuditMode {
		// Allow-but-log: nothing is blocked, but out-of-set calls are recorded.
		p.DefaultAction = ActLog
	} else {
		p.DefaultAction = ActErrno
		ret := opts.ErrnoRet
		if ret == 0 {
			ret = 1 // EPERM
		}
		p.DefaultErrnoRet = &ret
	}
	return p
}
