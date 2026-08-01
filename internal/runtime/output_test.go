package runtime

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileSinkWritesOneJSONLinePerRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	s, err := NewFileSink(path)
	if err != nil {
		t.Fatalf("NewFileSink: %v", err)
	}
	rec := DetectionRecord{Detection: Detection{RuleID: "DS-RAT-RT-001", Seq: 1}}
	for i := 0; i < 2; i++ {
		if err := s.Emit(rec); err != nil {
			t.Fatalf("Emit: %v", err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	f, _ := os.Open(path)
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		n++
	}
	if n != 2 {
		t.Fatalf("got %d lines, want 2", n)
	}
}

type sinkFunc func(DetectionRecord) error

func (f sinkFunc) Emit(r DetectionRecord) error { return f(r) }

type countingSink struct{ n int }

func (c *countingSink) Emit(DetectionRecord) error { c.n++; return nil }

func TestMultiSinkFansOutToAllEvenWhenOneFails(t *testing.T) {
	a := &countingSink{}
	failing := sinkFunc(func(DetectionRecord) error { return io.ErrClosedPipe })
	b := &countingSink{}
	m := &MultiSink{Sinks: []Sink{a, failing, b}}
	if err := m.Emit(DetectionRecord{}); err == nil {
		t.Fatalf("want joined error from failing sink")
	}
	if a.n != 1 || b.n != 1 {
		t.Fatalf("fanout stopped early: a=%d b=%d", a.n, b.n)
	}
}

func TestWebhookSinkPostsRecord(t *testing.T) {
	got := make(chan string, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- string(body)
	}))
	defer srv.Close()
	s := &WebhookSink{URL: srv.URL}
	if err := s.Emit(DetectionRecord{Detection: Detection{RuleID: "DS-RAT-RT-003"}}); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	if body := <-got; !strings.Contains(body, "DS-RAT-RT-003") {
		t.Fatalf("webhook body missing rule id: %s", body)
	}
}
