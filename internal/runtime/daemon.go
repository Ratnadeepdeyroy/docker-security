package runtime

import (
	"context"
	"errors"
	"io"
	"sort"
)

// This file is the daemon core: the loop that a `dsecrat-runtime` process runs on a
// node (DaemonSet-style). It pulls events from a source, feeds them through the
// detector, and for each detection plans a response, optionally captures a
// forensic bundle, and optionally builds an incident — then emits the result to
// a sink. Keeping the loop here (not in cmd/) makes the whole daemon behavior
// unit-testable against a replay source with no process/signal machinery.
//
// It maintains a small ring buffer of recent events so a detection can be sealed
// with the context that led to it. The loop reads no clock; over a replay source
// it is fully deterministic.

// DetectionRecord is one emitted result: the detection plus what the daemon did
// with it. Sinks render this; the daemon also returns the full ordered slice.
type DetectionRecord struct {
	Detection    Detection `json:"detection"`
	Action       Action    `json:"action"`
	Incident     *Incident `json:"incident,omitempty"`
	EvidencePath string    `json:"evidence_path,omitempty"`
}

// Sink consumes emitted records as they occur (for streaming output / SIEM). A
// nil sink is allowed — the daemon still returns the collected records.
type Sink interface {
	Emit(rec DetectionRecord) error
}

// DaemonConfig configures a daemon run. The zero value is a safe detect-only
// sensor with the default rule pack and no forensics.
type DaemonConfig struct {
	Options       Options
	Images        []ImageInventory
	Policy        ResponsePolicy
	Responder     Responder     // defaults to a RecordingResponder if nil
	ForensicsDir  string        // when set, seal a forensic bundle per detection
	WindowSize    int           // recent-event window kept for forensics (default 32)
	EmitIncidents bool          // when true, attach an Incident to each record
	Sink          Sink          // optional streaming consumer
	Exceptions    *ExceptionSet // operator-vetted suppressions; nil = suppress nothing
}

// DaemonResult is the summary of a run.
type DaemonResult struct {
	Records       []DetectionRecord
	EventsScanned int
	EvidencePaths []string
	Suppressed    int // detections matched an Exception and were dropped before response/forensics/sink
}

// Detections extracts just the detections from the records, in order.
func (r *DaemonResult) Detections() []Detection {
	out := make([]Detection, len(r.Records))
	for i, rec := range r.Records {
		out[i] = rec.Detection
	}
	return out
}

// Run executes the daemon loop over src until EOF (replay) or ctx cancellation
// (live). It returns whatever it gathered even on a mid-stream error, so a
// truncated capture still yields partial, ordered results.
func (c DaemonConfig) Run(ctx context.Context, src EventSource) (*DaemonResult, error) {
	if c.WindowSize <= 0 {
		c.WindowSize = 32
	}
	responder := c.Responder
	if responder == nil {
		responder = &RecordingResponder{}
	}
	det := NewDetector(c.Options, c.Images)
	ring := newEventRing(c.WindowSize)
	res := &DaemonResult{}

	loopErr := func() error {
		for {
			ev, err := src.Next(ctx)
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
			res.EventsScanned++
			ring.push(ev)
			for _, d := range det.Process(&ev) {
				if c.Exceptions != nil && c.Exceptions.Suppressed(d) {
					res.Suppressed++
					continue
				}
				rec := c.handle(d, ring, responder)
				res.Records = append(res.Records, rec)
				if rec.EvidencePath != "" {
					res.EvidencePaths = append(res.EvidencePaths, rec.EvidencePath)
				}
			}
		}
	}()

	// Canonical order regardless of how detections interleaved.
	sort.SliceStable(res.Records, func(i, j int) bool {
		di, dj := res.Records[i].Detection, res.Records[j].Detection
		if di.Seq != dj.Seq {
			return di.Seq < dj.Seq
		}
		return di.RuleID < dj.RuleID
	})
	return res, loopErr
}

// handle plans a response, captures forensics, and builds an incident for one
// detection, emitting the record to the sink. Sink/forensics errors are attached
// to the record path (empty on failure) but never abort the loop — a sensor must
// keep observing even if a side channel hiccups.
func (c DaemonConfig) handle(d Detection, ring *eventRing, responder Responder) DetectionRecord {
	action := c.Policy.Plan(d)
	_ = responder.Do(action)

	rec := DetectionRecord{Detection: d, Action: action}
	if c.EmitIncidents {
		rec.Incident = BuildIncident(d)
	}
	if c.ForensicsDir != "" {
		ev := CaptureForensics(d, ring.slice())
		if path, err := ev.WriteToDir(c.ForensicsDir); err == nil {
			rec.EvidencePath = path
		}
	}
	if c.Sink != nil {
		_ = c.Sink.Emit(rec)
	}
	return rec
}

// --- recent-event ring buffer --------------------------------------------

// eventRing is a fixed-size ring of the most recent events, used to give a
// forensic capture the context leading up to a detection.
type eventRing struct {
	buf  []Event
	size int
	n    int // total pushed
}

func newEventRing(size int) *eventRing {
	return &eventRing{buf: make([]Event, 0, size), size: size}
}

func (r *eventRing) push(ev Event) {
	if len(r.buf) < r.size {
		r.buf = append(r.buf, ev)
	} else {
		r.buf[r.n%r.size] = ev
	}
	r.n++
}

// slice returns the buffered events in chronological order (oldest→newest).
func (r *eventRing) slice() []Event {
	if len(r.buf) < r.size {
		out := make([]Event, len(r.buf))
		copy(out, r.buf)
		return out
	}
	out := make([]Event, 0, r.size)
	for i := 0; i < r.size; i++ {
		out = append(out, r.buf[(r.n+i)%r.size])
	}
	return out
}
