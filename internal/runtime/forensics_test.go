package runtime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

func sampleDetection() Detection {
	return Detection{
		RuleID:       "DS-RAT-RT-003",
		Severity:     engine.SeverityCritical,
		Title:        "Container escape attempt",
		Message:      "container-escape tool executed: nsenter",
		Technique:    techEscapeToHost,
		Seq:          6,
		TimeUnixNano: 6000,
		Container:    ContainerInfo{ID: "c1", ImageRef: "img:1"},
		Process:      ProcessInfo{PID: 903, Exe: "/usr/bin/nsenter", Ancestry: []string{"/usr/sbin/nginx", "/usr/bin/nsenter"}},
	}
}

func TestForensicCaptureAndVerify(t *testing.T) {
	window := []Event{
		{Seq: 5, Kind: KindProcess, Process: ProcessInfo{PID: 812, Exe: "/bin/sh"}},
		{Seq: 6, Kind: KindProcess, Process: ProcessInfo{PID: 903, Exe: "/usr/bin/nsenter"}},
	}
	ev := CaptureForensics(sampleDetection(), window)
	if ev.Algorithm != "sha256" || ev.Digest == "" {
		t.Fatal("evidence not sealed with a sha256 digest")
	}
	if !ev.Verify() {
		t.Fatal("freshly sealed evidence should verify")
	}
	// Determinism: sealing the same detection+window yields the same digest.
	ev2 := CaptureForensics(sampleDetection(), window)
	if ev.Digest != ev2.Digest {
		t.Errorf("non-deterministic digest: %s != %s", ev.Digest, ev2.Digest)
	}
}

func TestForensicTamperDetected(t *testing.T) {
	ev := CaptureForensics(sampleDetection(), nil)
	// Mutate the sealed bundle after the fact → digest must no longer match.
	ev.Bundle.Detection.Message = "tampered"
	if ev.Verify() {
		t.Error("tampered evidence must fail verification (chain of custody broken)")
	}
}

func TestForensicWriteIsWORM(t *testing.T) {
	dir := t.TempDir()
	ev := CaptureForensics(sampleDetection(), nil)
	path, err := ev.WriteToDir(dir)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if !strings.Contains(filepath.Base(path), ev.Digest[:16]) {
		t.Errorf("evidence filename %q should embed the digest", filepath.Base(path))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Read-only mode (write-once): owner/group read, no write bits.
	if info.Mode().Perm()&0o222 != 0 {
		t.Errorf("evidence file mode %v should have no write bits (WORM)", info.Mode().Perm())
	}
	// Writing the same evidence again is a no-op that returns the same path.
	path2, err := ev.WriteToDir(dir)
	if err != nil || path2 != path {
		t.Errorf("re-writing identical evidence should be a stable no-op, got %q err=%v", path2, err)
	}
	// The written bytes re-verify via the from-disk chain-of-custody check.
	data, _ := os.ReadFile(path)
	ok, err := VerifyEvidenceBytes(data)
	if err != nil {
		t.Fatalf("verify from disk: %v", err)
	}
	if !ok {
		t.Error("evidence read back from disk should verify")
	}
	// Tampering with the file breaks verification.
	tampered := []byte(strings.Replace(string(data), "nsenter", "notthis", 1))
	if ok, _ := VerifyEvidenceBytes(tampered); ok {
		t.Error("tampered on-disk evidence must fail verification")
	}
}

func TestForensicRedactsWindowArgs(t *testing.T) {
	window := []Event{{
		Seq: 1, Kind: KindProcess,
		Process: ProcessInfo{PID: 1, Exe: "/app", Args: []string{"app", "--password=SuperSecretValue123"}},
	}}
	ev := CaptureForensics(sampleDetection(), window)
	data, _ := json.Marshal(ev)
	if strings.Contains(string(data), "SuperSecretValue123") {
		t.Error("secret argv survived into the forensic bundle")
	}
}
