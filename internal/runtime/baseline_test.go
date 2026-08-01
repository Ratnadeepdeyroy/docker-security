package runtime

import (
	"context"
	"testing"
)

// benignStream is a small "normal behavior" capture used to learn a baseline.
func benignStream() ([]Event, string) {
	img := "sha256:svc"
	c := ContainerInfo{ID: "c1", ImageID: img, ImageRef: "svc:1"}
	return []Event{
		{Seq: 1, Kind: KindProcess, Container: c, Process: ProcessInfo{PID: 1, Exe: "/app/svc", Caps: []string{"CAP_NET_BIND_SERVICE"}}},
		{Seq: 2, Kind: KindSyscall, Container: c, Process: ProcessInfo{PID: 1, Exe: "/app/svc"}, Syscall: &SyscallEvent{Name: "epoll_wait"}},
		{Seq: 3, Kind: KindNetwork, Container: c, Process: ProcessInfo{PID: 1, Exe: "/app/svc"}, Network: &NetworkEvent{Op: "connect", RemoteIP: "10.0.0.5", RemotePort: 5432}},
		{Seq: 4, Kind: KindFile, Container: c, Process: ProcessInfo{PID: 1, Exe: "/app/svc"}, File: &FileEvent{Path: "/etc/app/config.yaml", Op: "read", Flags: "O_RDONLY"}},
		{Seq: 5, Kind: KindFile, Container: c, Process: ProcessInfo{PID: 1, Exe: "/app/svc"}, File: &FileEvent{Path: "/var/lib/app/state.db", Op: "write", Flags: "O_RDWR"}},
	}, img
}

func learnBaseline(t *testing.T, events []Event) *Baseline {
	t.Helper()
	det := NewDetector(Options{EnableAnomaly: true}, nil) // no baseline supplied → learning mode
	if _, err := det.Run(context.Background(), NewReplaySource(events)); err != nil {
		t.Fatalf("learning run: %v", err)
	}
	b := det.Baseline()
	if b == nil {
		t.Fatal("expected a learned baseline")
	}
	return b
}

func TestBaselineLearnsObservedBehavior(t *testing.T) {
	events, img := benignStream()
	b := learnBaseline(t, events)
	wp := b.Workloads[img]
	if wp == nil {
		t.Fatalf("no profile learned for %s", img)
	}
	if !wp.knowsExe("/app/svc") {
		t.Error("baseline should know the observed exe")
	}
	if !wp.knowsSyscall("epoll_wait") {
		t.Error("baseline should know the observed syscall")
	}
	if !wp.knowsEndpoint("10.0.0.5:5432") {
		t.Error("baseline should know the observed endpoint")
	}
	// The enriched profile also captures capabilities, file access by mode, and
	// network use — the full least-privilege surface Phase 7 consumes.
	if !contains(wp.Capabilities, "CAP_NET_BIND_SERVICE") {
		t.Error("baseline should capture observed capabilities")
	}
	if !contains(wp.FileReads, "/etc/app/config.yaml") {
		t.Error("baseline should capture file reads")
	}
	if !contains(wp.FileWrites, "/var/lib/app/state.db") {
		t.Error("baseline should capture file writes")
	}
	if !contains(wp.FileExecs, "/app/svc") {
		t.Error("baseline should capture executed binaries")
	}
	if !wp.Network {
		t.Error("baseline should record that the workload used the network")
	}
}

func TestAnomalyOffByDefault(t *testing.T) {
	// Even with a baseline present, the anomaly rule must not fire unless enabled.
	events, _ := benignStream()
	b := learnBaseline(t, events)

	novel := Event{Seq: 10, Kind: KindProcess,
		Container: ContainerInfo{ID: "c1", ImageID: "sha256:svc", ImageRef: "svc:1"},
		Process:   ProcessInfo{PID: 50, Exe: "/tmp/never-seen"},
	}
	// Default options: anomaly disabled.
	if fired(evalOne(t, Options{Baseline: b}, nil, novel), "DS-RAT-RT-050") {
		t.Error("anomaly rule fired without EnableAnomaly")
	}
}

func TestAnomalyFiresOnDeviation(t *testing.T) {
	events, _ := benignStream()
	b := learnBaseline(t, events)

	novel := Event{Seq: 10, Kind: KindProcess,
		Container: ContainerInfo{ID: "c1", ImageID: "sha256:svc", ImageRef: "svc:1"},
		Process:   ProcessInfo{PID: 50, Exe: "/tmp/never-seen"},
	}
	dets := evalOne(t, Options{EnableAnomaly: true, Baseline: b}, nil, novel)
	if !fired(dets, "DS-RAT-RT-050") {
		t.Error("unbaselined exe should trigger the anomaly rule when enabled")
	}

	// A baselined exe must NOT be flagged as anomalous.
	known := novel
	known.Process.Exe = "/app/svc"
	if fired(evalOne(t, Options{EnableAnomaly: true, Baseline: b}, nil, known), "DS-RAT-RT-050") {
		t.Error("a baselined exe should not be anomalous")
	}
}

// --- profile generation --------------------------------------------------

func TestGenerateSeccompProfile(t *testing.T) {
	events, img := benignStream()
	b := learnBaseline(t, events)

	prof := GenerateSeccompProfile(b, img)
	if prof == nil {
		t.Fatal("expected a generated profile")
	}
	if prof.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Errorf("default action = %q, want default-deny SCMP_ACT_ERRNO", prof.DefaultAction)
	}
	allowed := map[string]bool{}
	for _, rule := range prof.Syscalls {
		for _, n := range rule.Names {
			allowed[n] = true
		}
	}
	// Observed syscalls must be allowed...
	for _, want := range []string{"epoll_wait", "connect", "execve"} {
		if !allowed[want] {
			t.Errorf("generated profile omits observed syscall %q", want)
		}
	}
	// ...and the safety floor keeps the workload runnable.
	for _, want := range []string{"read", "write", "exit_group", "mmap"} {
		if !allowed[want] {
			t.Errorf("generated profile omits baseline-floor syscall %q", want)
		}
	}
	// Deterministic ordering: names are sorted.
	names := prof.Syscalls[0].Names
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("profile syscalls not sorted: %q > %q", names[i-1], names[i])
		}
	}
}

func TestGenerateSeccompProfileUnknownWorkload(t *testing.T) {
	events, _ := benignStream()
	b := learnBaseline(t, events)
	if GenerateSeccompProfile(b, "sha256:does-not-exist") != nil {
		t.Error("expected nil profile for an unknown workload")
	}
	if GenerateSeccompProfile(nil, "x") != nil {
		t.Error("expected nil profile for a nil baseline")
	}
}
