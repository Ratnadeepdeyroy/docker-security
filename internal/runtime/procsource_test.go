package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// writeFakeProc builds a minimal fixture under root/<pid>/ that mimics the
// /proc/<pid> layout readProcess parses: comm, cmdline, cgroup, status, and an
// exe.target file that stands in for the exe symlink (readlink of a real
// symlink is not testable on darwin, so the untagged parser reads this plain
// file as a shim; the real Linux source overrides Exe via os.Readlink).
func writeFakeProc(t *testing.T, root string, pid int, comm, exe, cgroup string) {
	t.Helper()
	d := filepath.Join(root, strconv.Itoa(pid))
	if err := os.MkdirAll(filepath.Join(d, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := func(name, content string) {
		if err := os.WriteFile(filepath.Join(d, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w("comm", comm+"\n")
	w("cmdline", exe+"\x00")
	w("cgroup", cgroup+"\n")
	w("status", "Name:\t"+comm+"\nPPid:\t1\nUid:\t0\t0\t0\t0\n")
	w("exe.target", exe)
}

func TestReadProcessParsesFixture(t *testing.T) {
	root := t.TempDir()
	const id = "3f7a1c2b9d8e4f60a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718"
	writeFakeProc(t, root, 1001, "sh", "/bin/sh", "0::/system.slice/docker-"+id+".scope")
	pi, cg, err := readProcess(root, 1001)
	if err != nil || pi.Comm != "sh" || pi.Exe != "/bin/sh" {
		t.Fatalf("readProcess: pi=%+v cg=%q err=%v", pi, cg, err)
	}
	if parseCgroupContainerID(cg) != id {
		t.Fatalf("cgroup attribution failed: %q", cg)
	}
}

func TestDiffProcTableEmitsExecForNewPID(t *testing.T) {
	prev := map[int]ProcessInfo{}
	cur := map[int]ProcessInfo{1001: {PID: 1001, Comm: "sh", Exe: "/bin/sh"}}
	evs := diffProcTable(prev, cur)
	if len(evs) != 1 || evs[0].Kind != KindProcess || evs[0].Process.Exe != "/bin/sh" {
		t.Fatalf("want one exec event, got %+v", evs)
	}
}

func TestDiffProcTableIgnoresUnchangedPID(t *testing.T) {
	tbl := map[int]ProcessInfo{1001: {PID: 1001, Exe: "/bin/sh"}}
	if evs := diffProcTable(tbl, tbl); len(evs) != 0 {
		t.Fatalf("want no events, got %d", len(evs))
	}
}

func TestReadTCPConnectionsDecodesRemote(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "5")
	os.MkdirAll(filepath.Join(d, "net"), 0o755)
	// remote 127.0.0.1:80 -> little-endian 0100007F, port 0050; state 01 ESTABLISHED
	line := "  0: 0100007F:9C40 0100007F:0050 01 00000000:00000000 00:00000000 00000000  1000        0 0 1 0\n"
	os.WriteFile(filepath.Join(d, "net", "tcp"), []byte("sl local rem st ...\n"+line), 0o644)
	conns := readTCPConnections(root, 5)
	if len(conns) == 0 || conns[0].RemoteIP != "127.0.0.1" || conns[0].RemotePort != 80 {
		t.Fatalf("decode failed: %+v", conns)
	}
}

func TestProcSourceEmitsFromSnapshots(t *testing.T) {
	snaps := []map[int]ProcessInfo{
		{},
		{1001: {PID: 1001, Comm: "sh", Exe: "/bin/sh"}},
		{1001: {PID: 1001, Comm: "sh", Exe: "/bin/sh"}}, // steady state -> EOF terminates
	}
	i := 0
	s := &ProcSource{interval: 0, snapshot: func() (map[int]ProcessInfo, error) {
		m := snaps[i]
		if i < len(snaps)-1 {
			i++
		}
		return m, nil
	}}
	ctx := context.Background()
	ev, err := s.Next(ctx)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if ev.Process.Exe != "/bin/sh" {
		t.Fatalf("want /bin/sh exec, got %+v", ev.Process)
	}
	if ev.Seq == 0 {
		t.Fatalf("Seq must be assigned (got 0)")
	}
}

func TestProcSourceRespectsContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := &ProcSource{interval: time.Hour, snapshot: func() (map[int]ProcessInfo, error) { return map[int]ProcessInfo{}, nil }}
	if _, err := s.Next(ctx); err == nil {
		t.Fatalf("cancelled ctx must return an error")
	}
}

// TestProcSourceDoesNotEOFOnSteadyStateWhenLive is the regression guard for the
// live-sensor EOF bug: with a real polling interval (>0), an idle node whose
// process table doesn't change between polls must NOT make Next return io.EOF
// (which the daemon would treat as end-of-stream and exit). Next must keep
// polling until the context is cancelled.
func TestProcSourceDoesNotEOFOnSteadyStateWhenLive(t *testing.T) {
	steady := map[int]ProcessInfo{1: {PID: 1, Comm: "init", Exe: "/sbin/init"}}
	s := &ProcSource{interval: 5 * time.Millisecond, snapshot: func() (map[int]ProcessInfo, error) {
		return steady, nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	// First call primes prev (emits the initial process), drain any queued events.
	for {
		_, err := s.Next(ctx)
		if err != nil {
			if err == context.DeadlineExceeded {
				return // correct: kept polling until ctx expired, never EOF'd
			}
			t.Fatalf("live steady-state Next returned %v, want context deadline (never io.EOF)", err)
		}
	}
}
