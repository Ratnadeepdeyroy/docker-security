package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/syslog"
	"net/http"
	"os"
	"sync"
	"time"
)

// WebhookSink delivers detection records to a human (or human-facing system)
// by POSTing a JSON payload to a configured URL — e.g. a Slack/Teams webhook
// or an incident-management endpoint. It is the "alert-to-human" sink.
type WebhookSink struct {
	URL    string
	Client *http.Client
}

// Emit JSON-encodes rec and POSTs it to s.URL. A non-2xx response is treated
// as a delivery failure.
func (s *WebhookSink) Emit(rec DetectionRecord) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	client := s.Client
	if client == nil {
		// A bounded default: Emit runs synchronously inside the detection loop,
		// so a hung or black-holed endpoint must not stall the sensor. Callers
		// wanting different behavior supply their own Client.
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Post(s.URL, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return errors.New("webhook sink: non-success status " + resp.Status)
	}
	return nil
}

// FileSink writes each detection record as a single JSON line to a local
// file, forming a durable, append-only JSONL audit trail that survives
// process restarts and can be replayed or shipped later.
type FileSink struct {
	mu  sync.Mutex
	f   *os.File
	enc *json.Encoder
}

// NewFileSink opens (creating if necessary) the file at path for append-only
// writes and returns a FileSink backed by it.
func NewFileSink(path string) (*FileSink, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	return &FileSink{f: f, enc: json.NewEncoder(f)}, nil
}

// Emit writes rec as a single JSON line, guarded by a mutex so concurrent
// callers never interleave partial lines.
func (s *FileSink) Emit(rec DetectionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(rec)
}

// Close closes the underlying file.
func (s *FileSink) Close() error {
	return s.f.Close()
}

// SyslogSink forwards detection records to the local syslog daemon (LOG_AUTHPRIV),
// making them consumable by a SIEM or other log-aggregation pipeline.
type SyslogSink struct {
	mu sync.Mutex
	w  *syslog.Writer
}

// NewSyslogSink dials the local syslog daemon using LOG_AUTHPRIV|LOG_WARNING
// and the given tag.
func NewSyslogSink(tag string) (*SyslogSink, error) {
	w, err := syslog.New(syslog.LOG_AUTHPRIV|syslog.LOG_WARNING, tag)
	if err != nil {
		return nil, err
	}
	return &SyslogSink{w: w}, nil
}

// Emit JSON-encodes rec and writes it to syslog at warning level.
func (s *SyslogSink) Emit(rec DetectionRecord) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Warning(string(body))
}

// Close closes the underlying syslog connection.
func (s *SyslogSink) Close() error {
	return s.w.Close()
}

// MultiSink fans a single detection record out to every configured Sink. It
// never short-circuits on error: every sink gets a chance to run, and any
// failures are collected and returned together via errors.Join.
type MultiSink struct {
	Sinks []Sink
}

// Emit calls Emit on every non-nil sink in m.Sinks, continuing past errors
// and returning the joined set of failures (nil if all succeeded).
func (m *MultiSink) Emit(rec DetectionRecord) error {
	var errs []error
	for _, sink := range m.Sinks {
		if sink == nil {
			continue
		}
		if err := sink.Emit(rec); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
