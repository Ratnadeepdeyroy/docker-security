package runtime

import "testing"

// --- fileless execution rule ----------------------------------------------

func TestFilelessRuleFiresOnAnonymousExec(t *testing.T) {
	for _, exe := range []string{"/dev/shm/payload", "memfd:x (deleted)", "/usr/bin/foo (deleted)"} {
		ev := Event{Kind: KindProcess, Seq: 1, Process: ProcessInfo{Exe: exe, PID: 9}}
		if !fired(evalOne(t, Options{}, nil, ev), "DS-RAT-RT-012") {
			t.Fatalf("want DS-RAT-RT-012 for exe=%q", exe)
		}
	}
}

func TestFilelessRuleFiresOnMemfdCreate(t *testing.T) {
	ev := Event{Kind: KindSyscall, Seq: 1, Syscall: &SyscallEvent{Name: "memfd_create"}}
	if !fired(evalOne(t, Options{}, nil, ev), "DS-RAT-RT-012") {
		t.Fatalf("want DS-RAT-RT-012 on memfd_create")
	}
}

func TestFilelessRuleIgnoresNormalExec(t *testing.T) {
	ev := Event{Kind: KindProcess, Seq: 1, Process: ProcessInfo{Exe: "/usr/sbin/nginx"}}
	if fired(evalOne(t, Options{}, nil, ev), "DS-RAT-RT-012") {
		t.Fatalf("false positive on /usr/sbin/nginx")
	}
}
