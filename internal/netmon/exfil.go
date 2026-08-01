package netmon

import (
	"fmt"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Data exfiltration ---------------------------------------------------
//
// Two shapes, one goal (getting data out):
//
//   * Volume  — a lot of bytes pushed to one external destination, especially
//     when the flow is upload-heavy (tx >> rx). This is the "someone tarred /etc
//     and curled it off-box" case.
//   * Low-and-slow — a modest but steady trickle to one destination over a long
//     window, engineered to stay under a volume alarm. The cumulative total and
//     the duration together are the tell.
//
// Both baseline per workload and per destination, which is why they run over the
// aggregated DestStats rather than the raw flows.

// detectExfil flags volume and low-and-slow exfiltration to external hosts.
func detectExfil(fl *FlowLog, o Options, now time.Time) []Anomaly {
	var out []Anomaly
	for _, d := range fl.ExternalDests() {
		if d.IMDS {
			continue // IMDS has its own, higher-priority detector
		}
		ratio := txRxRatio(d.BytesTx, d.BytesRx)

		// Volume exfil: large upload, and lopsided toward tx.
		if d.BytesTx >= o.ExfilMinBytes && ratio >= o.ExfilTxRxRatio {
			out = append(out, Anomaly{
				Kind:     KindExfil,
				Severity: engine.SeverityHigh,
				Workload: fl.Workload.ID,
				Dest:     d.Host,
				Title:    "High-volume upload to external host (possible data exfiltration)",
				Detail: fmt.Sprintf(
					"Workload %q sent %s to %s across %d connection(s) with a %.1f:1 upload:download ratio — an upload-dominant transfer to a single external destination.",
					fl.Workload.ID, humanBytes(d.BytesTx), d.Host, d.Count, ratio),
				Score: 0.9,
				Evidence: map[string]string{
					"bytes_tx":    fmt.Sprintf("%d", d.BytesTx),
					"bytes_rx":    fmt.Sprintf("%d", d.BytesRx),
					"tx_rx_ratio": fmt.Sprintf("%.2f", ratio),
					"connections": fmt.Sprintf("%d", d.Count),
				},
			})
			continue // one exfil verdict per destination; volume outranks low-and-slow
		}

		// Low-and-slow: sustained trickle. Requires a long observed span and a
		// cumulative volume that would be unremarkable per-connection.
		span := d.LastTS - d.FirstTS
		if d.BytesTx >= o.LowSlowMinBytes && span >= o.LowSlowMinSpanSec && d.Count >= o.BeaconMinSamples {
			out = append(out, Anomaly{
				Kind:     KindLowAndSlow,
				Severity: engine.SeverityMedium,
				Workload: fl.Workload.ID,
				Dest:     d.Host,
				Title:    "Low-and-slow egress to external host (possible staged exfiltration)",
				Detail: fmt.Sprintf(
					"Workload %q trickled %s to %s over %s in %d connection(s) — a steady low-volume flow consistent with exfiltration paced to evade volume alarms.",
					fl.Workload.ID, humanBytes(d.BytesTx), d.Host, humanDuration(span), d.Count),
				Score: 0.7,
				Evidence: map[string]string{
					"bytes_tx":    fmt.Sprintf("%d", d.BytesTx),
					"span_sec":    fmt.Sprintf("%d", span),
					"connections": fmt.Sprintf("%d", d.Count),
				},
			})
		}
	}
	_ = now // reserved for future "recent-only" windowing; kept for signature stability
	return out
}

// txRxRatio is bytes-out over bytes-in, guarding divide-by-zero. A pure upload
// (rx == 0) returns the tx count itself so it always clears any finite ratio
// threshold.
func txRxRatio(tx, rx int64) float64 {
	if rx <= 0 {
		return float64(tx)
	}
	return float64(tx) / float64(rx)
}

// humanBytes renders a byte count in binary units for readable finding text.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n/div >= unit && exp < 5 {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}

// humanDuration renders a second count as a compact h/m/s string.
func humanDuration(sec int64) string {
	d := time.Duration(sec) * time.Second
	return d.String()
}
