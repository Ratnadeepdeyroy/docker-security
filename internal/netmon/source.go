package netmon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// --- Flow source ---------------------------------------------------------
//
// Source is the seam that decouples Phase 6 from Phase 5. Detection and policy
// generation consume a Source and never care whether the events came from a
// live eBPF probe, a Phase-5 telemetry stream, or a recorded fixture. Phase 5
// (runtime telemetry) is being built in parallel; rather than import it (and
// couple our build to code that may not exist yet), we define this small local
// interface and let the master wire a Phase-5 adapter to it later — recorded as
// a master action in NOTES.md.

// Source yields a window of observed network telemetry. Implementations must
// return a Capture whose events are attributed to workloads; callers Normalize
// before analysis.
type Source interface {
	// Capture collects the currently available events. It must respect ctx and
	// must not block indefinitely.
	Capture(ctx context.Context) (*Capture, error)
}

// RecordedSource replays a Capture that was loaded from a fixture or an
// upstream recorder. It is the deterministic Source used in tests and in the
// offline `dsecrat net` path.
type RecordedSource struct{ cap *Capture }

// NewRecordedSource wraps an already-loaded capture as a Source.
func NewRecordedSource(c *Capture) *RecordedSource { return &RecordedSource{cap: c} }

// Capture returns the recorded window. The returned pointer is the stored
// capture; callers that mutate it should clone first.
func (s *RecordedSource) Capture(_ context.Context) (*Capture, error) {
	if s.cap == nil {
		return nil, fmt.Errorf("netmon: recorded source has no capture")
	}
	return s.cap, nil
}

// --- Loading recorded captures -------------------------------------------

// maxCaptureBytes bounds how large a capture we will read from disk. A hostile
// or corrupt fixture must not be able to exhaust memory; 64 MiB is far more than
// any realistic recorded window and keeps the tool's own attack surface small.
const maxCaptureBytes = 64 << 20

// LoadCapture reads a JSON capture from a file path, enforcing the size bound,
// and returns it normalized and ready to analyse.
func LoadCapture(path string) (*Capture, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open capture %q: %w", path, err)
	}
	defer f.Close()
	return DecodeCapture(io.LimitReader(f, maxCaptureBytes+1))
}

// DecodeCapture parses a JSON capture from r with the same size bound as
// LoadCapture. It rejects trailing garbage so a truncated-then-padded file is
// caught rather than silently half-read.
func DecodeCapture(r io.Reader) (*Capture, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read capture: %w", err)
	}
	if len(data) > maxCaptureBytes {
		return nil, fmt.Errorf("capture exceeds %d byte limit", maxCaptureBytes)
	}
	var c Capture
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("decode capture: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("decode capture: unexpected trailing data")
	}
	c.Normalize()
	return &c, nil
}

// Encode writes the capture as indented JSON — used to persist a fixture from a
// live/telemetry recording so it can be replayed deterministically in CI.
func (c *Capture) Encode(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(c)
}
