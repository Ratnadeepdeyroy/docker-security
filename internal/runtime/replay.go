package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

// --- Recorded scenarios (the offline, deterministic source) --------------

// Scenario is a recorded telemetry stream plus the image inventory needed to
// evaluate it. It is the committed-fixture format the whole engine is tested
// against, and the shape a real sensor would checkpoint for offline replay /
// incident reconstruction.
type Scenario struct {
	// Version guards the on-disk format so we can evolve it without silently
	// misreading old captures.
	Version int `json:"version"`
	// Name is a human label for the capture (used in reports/tests).
	Name string `json:"name,omitempty"`
	// Images is the per-image binary inventory. Drift detection asks whether an
	// executed path shipped in the image; without an entry for a container's
	// image, drift is simply not evaluated for that container (fail-open on data
	// we do not have, rather than crying wolf).
	Images []ImageInventory `json:"images,omitempty"`
	// Events is the ordered telemetry stream.
	Events []Event `json:"events"`
}

// ImageInventory lists the executable paths that shipped in an image. It is the
// bridge from the build-time phases (which know an image's contents) to runtime
// drift detection.
type ImageInventory struct {
	ImageID  string   `json:"image_id,omitempty"`
	ImageRef string   `json:"image_ref,omitempty"`
	Binaries []string `json:"binaries"`
}

// scenarioSizeLimit bounds how much recorded telemetry we will parse from an
// untrusted file, so a hostile or corrupt capture cannot exhaust memory.
const scenarioSizeLimit = 64 << 20 // 64 MiB

// LoadScenario decodes a Scenario from JSON, defending against oversized input
// and normalizing event order by Seq so replay is deterministic regardless of
// how the file was written.
func LoadScenario(r io.Reader) (*Scenario, error) {
	limited := io.LimitReader(r, scenarioSizeLimit+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read scenario: %w", err)
	}
	if len(data) > scenarioSizeLimit {
		return nil, fmt.Errorf("scenario exceeds %d byte limit", scenarioSizeLimit)
	}
	var sc Scenario
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sc); err != nil {
		return nil, fmt.Errorf("decode scenario: %w", err)
	}
	if sc.Version == 0 {
		sc.Version = 1
	}
	if sc.Version != 1 {
		return nil, fmt.Errorf("unsupported scenario version %d (want 1)", sc.Version)
	}
	// Stable order: sort by Seq. A capture written out of order still replays
	// identically, and golden tests never depend on file ordering.
	sort.SliceStable(sc.Events, func(i, j int) bool { return sc.Events[i].Seq < sc.Events[j].Seq })
	return &sc, nil
}

// ReplaySource plays a fixed slice of events back in order. It is bounded:
// after the last event Next returns io.EOF. This is the deterministic source
// the detector and daemon run against in tests, CI, and offline forensics.
type ReplaySource struct {
	events []Event
	i      int
}

// NewReplaySource returns a source that yields the given events in slice order.
// The caller is expected to have ordered them (LoadScenario does).
func NewReplaySource(events []Event) *ReplaySource {
	return &ReplaySource{events: events}
}

// Next yields the next recorded event, or io.EOF when drained. It honors ctx so
// a cancelled run stops promptly even mid-replay.
func (s *ReplaySource) Next(ctx context.Context) (Event, error) {
	if err := ctx.Err(); err != nil {
		return Event{}, err
	}
	if s.i >= len(s.events) {
		return Event{}, io.EOF
	}
	ev := s.events[s.i]
	s.i++
	return ev, nil
}

// Close is a no-op; a replay source owns no resources.
func (s *ReplaySource) Close() error { return nil }
