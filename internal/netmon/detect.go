package netmon

import (
	"sort"
	"time"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Detection orchestration ---------------------------------------------

// AnomalyKind names a detected behaviour. Kinds are stable strings so the
// netpolicy module can map each to a DS-RAT-NET rule id and the right references.
type AnomalyKind string

const (
	KindIMDS        AnomalyKind = "imds_access"
	KindBeacon      AnomalyKind = "c2_beacon"
	KindExfil       AnomalyKind = "exfil_volume"
	KindLowAndSlow  AnomalyKind = "exfil_low_and_slow"
	KindLateral     AnomalyKind = "lateral_movement"
	KindDNSTunnel   AnomalyKind = "dns_tunnel"
	KindDGA         AnomalyKind = "dns_dga"
	KindBlockedEg   AnomalyKind = "blocked_egress"
	KindAgentEgress AnomalyKind = "agent_egress_unknown" // AI-age feature (off by default)
	KindAnomalousEg AnomalyKind = "anomalous_egress"     // AI-age feature (off by default)
	KindHostNetwork AnomalyKind = "host_network"
	KindFreeForAll  AnomalyKind = "unrestricted_east_west"
)

// Anomaly is one detection result, scoped to a workload. Severity speaks the
// engine's language so the module adapter is a straight projection. Evidence is
// a small, machine-consumable map an agent can reason over — the "explain"
// half of the AI-age mandate lives here.
type Anomaly struct {
	Kind     AnomalyKind
	Severity engine.Severity
	Workload string
	Dest     string  // human destination summary, "" for workload-scoped anomalies
	Title    string  // one human line
	Detail   string  // why it fired
	Score    float64 // 0..1 confidence, deterministic
	Evidence map[string]string
}

// Options tunes detection. The zero value is a safe, deterministic default with
// the AI-age features OFF — callers opt in explicitly. Thresholds are exposed so
// they can be tightened per environment without editing the heuristics.
type Options struct {
	// Now is the reference time. Zero means "derive from the capture window",
	// which keeps analysis deterministic without any wall-clock read.
	Now time.Time

	// Beaconing.
	BeaconMinSamples int     // minimum connections to a dest before periodicity is meaningful
	BeaconMaxCV      float64 // max coefficient of variation of intervals to call it regular
	BeaconMaxBytes   int64   // per-connection byte ceiling; beacons are small

	// Exfiltration.
	ExfilMinBytes     int64   // total egress bytes to one external dest to flag volume exfil
	ExfilTxRxRatio    float64 // tx:rx ratio above which traffic is upload-heavy
	LowSlowMinBytes   int64   // cumulative bytes for low-and-slow
	LowSlowMinSpanSec int64   // minimum duration for low-and-slow

	// Lateral movement.
	LateralMinPeers int // distinct internal peers before fan-out is suspicious

	// DNS.
	DNSTunnelMinQueries int     // queries under one parent before tunnelling is considered
	DNSEntropyThreshold float64 // Shannon entropy (bits/char) above which a label looks generated
	DGAMinNXDomain      int     // NXDOMAIN responses before a DGA is considered

	// AI-age features (off by default).
	EnableAgentEgress bool // flag AI-agent workloads reaching unknown model/inference hosts
	EnableIntent      bool // cluster destinations into intended vs anomalous
	IntentMinCount    int  // connection count at/above which a dest is "intended" (baseline)
}

// withDefaults returns o with any zero threshold replaced by a vetted default.
// Callers get sane behaviour from Options{} while retaining the ability to
// override any single knob.
func (o Options) withDefaults() Options {
	if o.BeaconMinSamples == 0 {
		o.BeaconMinSamples = 4
	}
	if o.BeaconMaxCV == 0 {
		o.BeaconMaxCV = 0.15
	}
	if o.BeaconMaxBytes == 0 {
		o.BeaconMaxBytes = 4096
	}
	if o.ExfilMinBytes == 0 {
		o.ExfilMinBytes = 10 << 20 // 10 MiB
	}
	if o.ExfilTxRxRatio == 0 {
		o.ExfilTxRxRatio = 8.0
	}
	if o.LowSlowMinBytes == 0 {
		o.LowSlowMinBytes = 1 << 20 // 1 MiB
	}
	if o.LowSlowMinSpanSec == 0 {
		o.LowSlowMinSpanSec = 3600 // an hour
	}
	if o.LateralMinPeers == 0 {
		o.LateralMinPeers = 10
	}
	if o.DNSTunnelMinQueries == 0 {
		o.DNSTunnelMinQueries = 20
	}
	if o.DNSEntropyThreshold == 0 {
		o.DNSEntropyThreshold = 3.6
	}
	if o.DGAMinNXDomain == 0 {
		o.DGAMinNXDomain = 10
	}
	if o.IntentMinCount == 0 {
		o.IntentMinCount = 3
	}
	return o
}

// now resolves the reference time without ever reading the wall clock: an
// explicit Options.Now wins, otherwise the latest event in the capture.
func (o Options) now(logs []*FlowLog) time.Time {
	if !o.Now.IsZero() {
		return o.Now
	}
	var latest int64
	for _, fl := range logs {
		for _, d := range fl.Dests {
			if d.LastTS > latest {
				latest = d.LastTS
			}
		}
		for _, ev := range fl.DNS {
			if ev.TSUnix > latest {
				latest = ev.TSUnix
			}
		}
	}
	return time.Unix(latest, 0).UTC()
}

// Report is the full deterministic result of analysing a capture: the derived
// per-workload flow logs plus every anomaly, sorted stably.
type Report struct {
	Logs      []*FlowLog
	Anomalies []Anomaly
}

// Highest returns the most severe anomaly severity in the report, or
// SeverityUnknown when there are none — used for --fail-on gating.
func (r *Report) Highest() engine.Severity {
	h := engine.SeverityUnknown
	for _, a := range r.Anomalies {
		if a.Severity > h {
			h = a.Severity
		}
	}
	return h
}

// Analyze runs every detector over a capture and returns a deterministic report.
// It builds the per-workload flow logs once and hands them to each heuristic.
func Analyze(c *Capture, opts Options) *Report {
	o := opts.withDefaults()
	c.Normalize()
	logs := BuildFlowLogs(c)
	now := o.now(logs)

	var anomalies []Anomaly
	for _, fl := range logs {
		anomalies = append(anomalies, detectIMDS(fl)...)
		anomalies = append(anomalies, detectBeacon(fl, o)...)
		anomalies = append(anomalies, detectExfil(fl, o, now)...)
		anomalies = append(anomalies, detectLateral(fl, o)...)
		anomalies = append(anomalies, detectDNS(fl, o)...)
		anomalies = append(anomalies, detectBlockedEgress(fl)...)
		anomalies = append(anomalies, detectHostNetwork(fl)...)
		if o.EnableAgentEgress {
			anomalies = append(anomalies, detectAgentEgress(fl)...)
		}
		if o.EnableIntent {
			anomalies = append(anomalies, detectAnomalousEgress(fl, o)...)
		}
	}
	sortAnomalies(anomalies)
	return &Report{Logs: logs, Anomalies: anomalies}
}

// sortAnomalies imposes a total, stable order: severity desc, then kind,
// workload, dest. Stable ordering is what makes the golden tests reproducible.
func sortAnomalies(a []Anomaly) {
	sort.SliceStable(a, func(i, j int) bool {
		if a[i].Severity != a[j].Severity {
			return a[i].Severity > a[j].Severity
		}
		if a[i].Kind != a[j].Kind {
			return a[i].Kind < a[j].Kind
		}
		if a[i].Workload != a[j].Workload {
			return a[i].Workload < a[j].Workload
		}
		return a[i].Dest < a[j].Dest
	})
}

// detectHostNetwork flags a workload sharing the host network namespace: it
// bypasses per-pod NetworkPolicy entirely, so egress control cannot contain it.
func detectHostNetwork(fl *FlowLog) []Anomaly {
	if !fl.Workload.HostNetwork {
		return nil
	}
	return []Anomaly{{
		Kind:     KindHostNetwork,
		Severity: engine.SeverityMedium,
		Workload: fl.Workload.ID,
		Title:    "Workload runs with host network namespace",
		Detail:   "hostNetwork removes network-namespace isolation; NetworkPolicy/egress rules do not apply to this pod.",
		Score:    1.0,
		Evidence: map[string]string{"host_network": "true"},
	}}
}
