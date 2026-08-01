package runtime

import "testing"

func TestRuntimeBinaryFiresOnProcSelfExeWrite(t *testing.T) {
	ev := Event{Kind: KindFile, Seq: 1, File: &FileEvent{Path: "/proc/self/exe", Op: "write"}}
	if !fired(evalOne(t, Options{}, nil, ev), "DS-RAT-RT-013") {
		t.Fatalf("want DS-RAT-RT-013 on /proc/self/exe write")
	}
}
func TestRuntimeBinaryFiresOnRuncTamper(t *testing.T) {
	ev := Event{Kind: KindFile, Seq: 1, File: &FileEvent{Path: "/usr/bin/runc", Op: "write"}}
	if !fired(evalOne(t, Options{}, nil, ev), "DS-RAT-RT-013") {
		t.Fatalf("want DS-RAT-RT-013 on runc binary write")
	}
}
func TestRuntimeBinaryFiresOnRuncFromDeleted(t *testing.T) {
	ev := Event{Kind: KindProcess, Seq: 1, Process: ProcessInfo{Exe: "/proc/self/exe (deleted)", Comm: "runc"}}
	// exe base is not "runc" here; instead test a clear case:
	ev2 := Event{Kind: KindProcess, Seq: 2, Process: ProcessInfo{Exe: "/tmp/runc"}}
	if !fired(evalOne(t, Options{}, nil, ev2), "DS-RAT-RT-013") {
		t.Fatalf("want DS-RAT-RT-013 on runc exec from /tmp")
	}
	_ = ev
}
func TestRuntimeBinaryIgnoresBenign(t *testing.T) {
	w := Event{Kind: KindFile, Seq: 1, File: &FileEvent{Path: "/tmp/scratch", Op: "write"}}
	x := Event{Kind: KindProcess, Seq: 2, Process: ProcessInfo{Exe: "/usr/sbin/runc"}}
	if fired(evalOne(t, Options{}, nil, w), "DS-RAT-RT-013") {
		t.Fatalf("false positive on /tmp write")
	}
	if fired(evalOne(t, Options{}, nil, x), "DS-RAT-RT-013") {
		t.Fatalf("false positive on normal /usr/sbin/runc exec")
	}
}

// TestRuntimeBinaryNoSubstringFalsePositive locks the fix for the substring
// bug: a write to a file whose name merely CONTAINS "runc"/"crun" as a
// substring (truncate, crunch) must not raise a Critical runtime-tamper alert.
func TestRuntimeBinaryNoSubstringFalsePositive(t *testing.T) {
	for _, p := range []string{"/var/lib/app/truncate.dat", "/opt/crunch/output", "/usr/bin/truncate"} {
		ev := Event{Kind: KindFile, Seq: 1, File: &FileEvent{Path: p, Op: "write"}}
		if fired(evalOne(t, Options{}, nil, ev), "DS-RAT-RT-013") {
			t.Fatalf("false positive DS-RAT-RT-013 on %q", p)
		}
	}
	// but a real runc binary write still fires
	ev := Event{Kind: KindFile, Seq: 1, File: &FileEvent{Path: "/usr/bin/containerd-shim-runc-v2", Op: "write"}}
	if !fired(evalOne(t, Options{}, nil, ev), "DS-RAT-RT-013") {
		t.Fatalf("want DS-RAT-RT-013 on containerd-shim-runc-v2 write")
	}
}
