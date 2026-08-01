package netmon

import (
	"fmt"
	"math"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- C2 beaconing --------------------------------------------------------
//
// A command-and-control implant "phones home" on a timer. The tell is not the
// destination (which may be a legitimate-looking CDN) but the *rhythm*: many
// connections at a near-constant interval, each carrying little data. We measure
// that rhythm with the coefficient of variation (CV = stddev/mean) of the
// inter-arrival gaps. Human/organic traffic is bursty (high CV); a beacon is
// metronomic (low CV). This is the timing/periodicity signal Zeek/RITA-style
// tools use, reimplemented on our own flow model.

// intervalStats summarises the gaps between consecutive connections.
type intervalStats struct {
	n      int
	mean   float64
	stddev float64
	cv     float64 // coefficient of variation; lower = more regular
}

// computeIntervalStats returns the stats of the gaps between ascending
// timestamps. Fewer than two gaps is not enough to speak of periodicity.
func computeIntervalStats(ts []int64) (intervalStats, bool) {
	if len(ts) < 3 { // need >= 2 intervals for a meaningful stddev
		return intervalStats{}, false
	}
	gaps := make([]float64, 0, len(ts)-1)
	for i := 1; i < len(ts); i++ {
		gaps = append(gaps, float64(ts[i]-ts[i-1]))
	}
	var sum float64
	for _, g := range gaps {
		sum += g
	}
	mean := sum / float64(len(gaps))
	if mean <= 0 {
		return intervalStats{}, false // all connections at the same instant: not a timed beacon
	}
	var sq float64
	for _, g := range gaps {
		d := g - mean
		sq += d * d
	}
	std := math.Sqrt(sq / float64(len(gaps)))
	return intervalStats{n: len(gaps), mean: mean, stddev: std, cv: std / mean}, true
}

// detectBeacon flags destinations contacted on a regular, low-jitter schedule
// with small per-connection payloads. Internal and IMDS destinations are left
// to their own detectors; beaconing is an egress-to-internet concern.
func detectBeacon(fl *FlowLog, o Options) []Anomaly {
	var out []Anomaly
	for _, d := range fl.Dests {
		if d.IMDS || d.Internal {
			continue
		}
		if d.Count < o.BeaconMinSamples {
			continue
		}
		stats, ok := computeIntervalStats(d.Timestamps)
		if !ok || stats.cv > o.BeaconMaxCV {
			continue
		}
		// Beacons are chatty but not bulky. A high average payload points at a
		// legitimate long-poll/stream rather than a callback.
		avgBytes := (d.BytesTx + d.BytesRx) / int64(d.Count)
		if avgBytes > o.BeaconMaxBytes {
			continue
		}
		// Regularity → confidence: CV of 0 is a perfect metronome (score 1),
		// approaching the threshold drops toward 0.5.
		score := 1.0 - (stats.cv / o.BeaconMaxCV / 2)
		out = append(out, Anomaly{
			Kind:     KindBeacon,
			Severity: engine.SeverityHigh,
			Workload: fl.Workload.ID,
			Dest:     d.Host,
			Title:    "Periodic C2 beaconing pattern to external host",
			Detail: fmt.Sprintf(
				"%d connections to %s at a near-constant %.0fs interval (jitter CV %.3f), averaging %d bytes each — the low-jitter, low-volume signature of an automated callback.",
				d.Count, d.Host, stats.mean, stats.cv, avgBytes),
			Score: round3(score),
			Evidence: map[string]string{
				"interval_sec": fmt.Sprintf("%.0f", stats.mean),
				"jitter_cv":    fmt.Sprintf("%.3f", stats.cv),
				"connections":  fmt.Sprintf("%d", d.Count),
				"avg_bytes":    fmt.Sprintf("%d", avgBytes),
			},
		})
	}
	return out
}

// round3 rounds a score to three decimals so JSON/goldens stay stable across
// platforms with different float-formatting quirks.
func round3(f float64) float64 { return math.Round(f*1000) / 1000 }
