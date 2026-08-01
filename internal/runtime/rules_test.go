package runtime

import (
	"context"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// evalOne runs one event through a fresh detector with the given options and
// returns the detections, so rule edge-cases can be probed in isolation.
func evalOne(t *testing.T, opts Options, images []ImageInventory, ev Event) []Detection {
	t.Helper()
	det := NewDetector(opts, images)
	out, err := det.Run(context.Background(), NewReplaySource([]Event{ev}))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return out
}

func fired(dets []Detection, ruleID string) bool {
	for _, d := range dets {
		if d.RuleID == ruleID {
			return true
		}
	}
	return false
}

// --- shell rule ----------------------------------------------------------

func TestShellEntrypointNotFlagged(t *testing.T) {
	// A shell that IS the container entrypoint lineage is benign and must not fire.
	ev := Event{Seq: 1, Kind: KindProcess,
		Container: ContainerInfo{ID: "c1"},
		Process:   ProcessInfo{PID: 1, Exe: "/bin/sh", Comm: "sh", Ancestry: []string{"/bin/sh"}},
	}
	if fired(evalOne(t, Options{}, nil, ev), "DS-RAT-RT-001") {
		t.Error("shell-as-entrypoint should not trigger DS-RAT-RT-001")
	}
}

func TestShellSpawnedByServiceFlagged(t *testing.T) {
	ev := Event{Seq: 1, Kind: KindProcess,
		Container: ContainerInfo{ID: "c1"},
		Process:   ProcessInfo{PID: 900, Exe: "/bin/bash", Comm: "bash", Ancestry: []string{"/pause", "/usr/sbin/nginx", "/bin/bash"}},
	}
	if !fired(evalOne(t, Options{}, nil, ev), "DS-RAT-RT-001") {
		t.Error("service-spawned shell should trigger DS-RAT-RT-001")
	}
}

// --- drift rule ----------------------------------------------------------

func TestDriftSilentWithoutInventory(t *testing.T) {
	// No image inventory → drift cannot be judged → must stay silent (no false alarms).
	ev := Event{Seq: 1, Kind: KindProcess,
		Container: ContainerInfo{ID: "c1", ImageID: "sha256:x"},
		Process:   ProcessInfo{PID: 900, Exe: "/tmp/dropper"},
	}
	if fired(evalOne(t, Options{}, nil, ev), "DS-RAT-RT-002") {
		t.Error("drift must not fire without an image inventory")
	}
}

func TestDriftSilentForImageBinary(t *testing.T) {
	images := []ImageInventory{{ImageID: "sha256:x", Binaries: []string{"/usr/sbin/nginx"}}}
	ev := Event{Seq: 1, Kind: KindProcess,
		Container: ContainerInfo{ID: "c1", ImageID: "sha256:x"},
		Process:   ProcessInfo{PID: 1, Exe: "/usr/sbin/nginx"},
	}
	if fired(evalOne(t, Options{}, images, ev), "DS-RAT-RT-002") {
		t.Error("a binary that shipped in the image must not be drift")
	}
}

func TestDriftFiresForNonImageBinary(t *testing.T) {
	images := []ImageInventory{{ImageID: "sha256:x", Binaries: []string{"/usr/sbin/nginx"}}}
	ev := Event{Seq: 1, Kind: KindProcess,
		Container: ContainerInfo{ID: "c1", ImageID: "sha256:x"},
		Process:   ProcessInfo{PID: 900, Exe: "/tmp/dropper"},
	}
	if !fired(evalOne(t, Options{}, images, ev), "DS-RAT-RT-002") {
		t.Error("a binary not in the image must be flagged as drift")
	}
}

// --- escape rule ---------------------------------------------------------

func TestEscapeViaHostPath(t *testing.T) {
	ev := Event{Seq: 1, Kind: KindFile,
		Container: ContainerInfo{ID: "c1"},
		Process:   ProcessInfo{PID: 900, Exe: "/bin/cat"},
		File:      &FileEvent{Path: "/var/run/docker.sock", Op: "open", Flags: "O_RDWR"},
	}
	dets := evalOne(t, Options{}, nil, ev)
	if !fired(dets, "DS-RAT-RT-003") {
		t.Error("access to the docker socket should trigger escape DS-RAT-RT-003")
	}
}

func TestEscapeSeverityIsCritical(t *testing.T) {
	ev := Event{Seq: 1, Kind: KindProcess,
		Container: ContainerInfo{ID: "c1"},
		Process:   ProcessInfo{PID: 900, Exe: "/usr/bin/nsenter"},
	}
	for _, d := range evalOne(t, Options{}, nil, ev) {
		if d.RuleID == "DS-RAT-RT-003" && d.Severity != engine.SeverityCritical {
			t.Errorf("escape severity = %v, want CRITICAL", d.Severity)
		}
	}
}

// --- credential / egress interplay ---------------------------------------

func TestIMDSNotDoubleReported(t *testing.T) {
	// IMDS egress is DS-RAT-RT-005's job; DS-RAT-RT-007 must not also fire on it.
	ev := Event{Seq: 1, Kind: KindNetwork,
		Container: ContainerInfo{ID: "c1"},
		Process:   ProcessInfo{PID: 900, Exe: "/bin/cat"},
		Network:   &NetworkEvent{Op: "connect", RemoteIP: "169.254.169.254", RemotePort: 80, Direction: "egress"},
	}
	dets := evalOne(t, Options{}, nil, ev)
	if !fired(dets, "DS-RAT-RT-005") {
		t.Error("IMDS connect should trigger DS-RAT-RT-005")
	}
	if fired(dets, "DS-RAT-RT-007") {
		t.Error("IMDS connect should NOT also trigger the generic egress rule DS-RAT-RT-007")
	}
}

func TestEgressAllowlistSuppressesKnownGood(t *testing.T) {
	opts := Options{EgressAllow: []string{"10.0.0.0/8", "api.internal"}}
	// Inside the allowlisted CIDR on a normal port → no detection.
	ev := Event{Seq: 1, Kind: KindNetwork,
		Container: ContainerInfo{ID: "c1"},
		Process:   ProcessInfo{PID: 900, Exe: "/app/svc"},
		Network:   &NetworkEvent{Op: "connect", RemoteIP: "10.1.2.3", RemotePort: 8080, Direction: "egress"},
	}
	if fired(evalOne(t, opts, nil, ev), "DS-RAT-RT-007") {
		t.Error("allowlisted CIDR egress should not fire DS-RAT-RT-007")
	}
	// Outside the allowlist → flagged.
	ev.Network.RemoteIP = "203.0.113.9"
	if !fired(evalOne(t, opts, nil, ev), "DS-RAT-RT-007") {
		t.Error("egress outside the allowlist should fire DS-RAT-RT-007")
	}
}

// --- privilege escalation ------------------------------------------------

func TestDangerousCapabilityFlagged(t *testing.T) {
	ev := Event{Seq: 1, Kind: KindProcess,
		Container: ContainerInfo{ID: "c1"},
		Process:   ProcessInfo{PID: 900, Exe: "/app/svc", Caps: []string{"CAP_CHOWN", "CAP_SYS_ADMIN"}},
	}
	if !fired(evalOne(t, Options{}, nil, ev), "DS-RAT-RT-009") {
		t.Error("a process holding CAP_SYS_ADMIN should trigger DS-RAT-RT-009")
	}
}

// --- reverse shell -------------------------------------------------------

func TestReverseShellViaSocketStdio(t *testing.T) {
	ev := Event{Seq: 1, Kind: KindProcess,
		Container: ContainerInfo{ID: "c1"},
		Process:   ProcessInfo{PID: 900, Exe: "/bin/bash", Comm: "bash", StdioSocket: true, Ancestry: []string{"/usr/sbin/nginx", "/bin/bash"}},
	}
	if !fired(evalOne(t, Options{}, nil, ev), "DS-RAT-RT-010") {
		t.Error("a shell with socket-backed stdio should trigger DS-RAT-RT-010")
	}
}

// --- kernel abuse --------------------------------------------------------

func TestKernelModuleLoadCritical(t *testing.T) {
	ev := Event{Seq: 1, Kind: KindSyscall,
		Container: ContainerInfo{ID: "c1"},
		Process:   ProcessInfo{PID: 900, Exe: "/sbin/insmod"},
		Syscall:   &SyscallEvent{Name: "finit_module", Args: map[string]string{"module": "evil.ko"}},
	}
	dets := evalOne(t, Options{}, nil, ev)
	if !fired(dets, "DS-RAT-RT-008") {
		t.Fatal("finit_module should trigger DS-RAT-RT-008")
	}
	for _, d := range dets {
		if d.RuleID == "DS-RAT-RT-008" && d.Severity != engine.SeverityCritical {
			t.Errorf("kernel abuse severity = %v, want CRITICAL", d.Severity)
		}
	}
}
