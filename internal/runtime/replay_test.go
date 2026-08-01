package runtime

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestLoadScenarioSortsBySeq(t *testing.T) {
	// Events written out of order must replay in Seq order.
	in := `{"version":1,"events":[
		{"seq":3,"kind":"process","process":{"exe":"/c"}},
		{"seq":1,"kind":"process","process":{"exe":"/a"}},
		{"seq":2,"kind":"process","process":{"exe":"/b"}}
	]}`
	sc, err := LoadScenario(strings.NewReader(in))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := []string{"/a", "/b", "/c"}
	for i, ev := range sc.Events {
		if ev.Process.Exe != want[i] {
			t.Errorf("event %d: got exe %q, want %q", i, ev.Process.Exe, want[i])
		}
	}
}

func TestLoadScenarioRejectsUnknownVersion(t *testing.T) {
	_, err := LoadScenario(strings.NewReader(`{"version":2,"events":[]}`))
	if err == nil {
		t.Fatal("expected error for unsupported version")
	}
}

func TestLoadScenarioRejectsUnknownField(t *testing.T) {
	// DisallowUnknownFields guards against silently misreading a capture.
	_, err := LoadScenario(strings.NewReader(`{"version":1,"events":[],"bogus":true}`))
	if err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestLoadScenarioDefaultsVersion(t *testing.T) {
	sc, err := LoadScenario(strings.NewReader(`{"events":[]}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if sc.Version != 1 {
		t.Errorf("expected version defaulted to 1, got %d", sc.Version)
	}
}

func TestReplaySourceEOFAndCancel(t *testing.T) {
	src := NewReplaySource([]Event{{Seq: 1}, {Seq: 2}})
	ctx := context.Background()
	if _, err := src.Next(ctx); err != nil {
		t.Fatalf("first next: %v", err)
	}
	if _, err := src.Next(ctx); err != nil {
		t.Fatalf("second next: %v", err)
	}
	if _, err := src.Next(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("expected io.EOF after drain, got %v", err)
	}

	// A cancelled context stops replay promptly.
	src2 := NewReplaySource([]Event{{Seq: 1}})
	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := src2.Next(cctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestLiveSourceUnavailableOffLinux(t *testing.T) {
	// On this build machine (darwin) live capture is unsupported; the daemon
	// must get a clear, non-panicking error so it can fall back to replay.
	_, err := NewLiveSource(LiveConfig{})
	if err == nil {
		t.Fatal("expected NewLiveSource to error on this platform")
	}
}
