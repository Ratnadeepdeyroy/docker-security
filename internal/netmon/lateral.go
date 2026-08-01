package netmon

import (
	"fmt"
	"sort"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Lateral movement & verdict alerting ---------------------------------

// detectLateral flags east-west fan-out: a single workload reaching an unusual
// number of distinct internal peers. Post-compromise lateral movement (scanning
// for the next hop, spraying an exploit across the subnet) shows up as a sudden
// widening of the internal peer set — normal service-to-service traffic talks to
// a handful of known dependencies, not the whole namespace.
func detectLateral(fl *FlowLog, o Options) []Anomaly {
	peers := map[string]bool{}
	ports := map[uint16]bool{}
	for _, d := range fl.Dests {
		if !d.Internal || d.IMDS {
			continue
		}
		peers[d.Host] = true
		ports[d.Port] = true
	}
	if len(peers) < o.LateralMinPeers {
		return nil
	}
	// Reaching many peers across many distinct ports looks more like scanning
	// than a fixed set of service dependencies; nudge severity up in that case.
	sev := engine.SeverityMedium
	if len(ports) >= o.LateralMinPeers {
		sev = engine.SeverityHigh
	}
	return []Anomaly{{
		Kind:     KindLateral,
		Severity: sev,
		Workload: fl.Workload.ID,
		Title:    "Lateral-movement fan-out across internal peers",
		Detail: fmt.Sprintf(
			"Workload %q connected to %d distinct internal peers across %d distinct port(s) — a fan-out consistent with east-west scanning or lateral movement rather than a fixed dependency set.",
			fl.Workload.ID, len(peers), len(ports)),
		Score: 0.75,
		Evidence: map[string]string{
			"distinct_peers": fmt.Sprintf("%d", len(peers)),
			"distinct_ports": fmt.Sprintf("%d", len(ports)),
			"sample_peers":   sampleKeys(peers, 5),
		},
	}}
}

// detectBlockedEgress surfaces flows the dataplane already dropped. A workload
// repeatedly hitting a deny rule is either misconfigured or actively probing for
// a way out; either way an operator wants to know. This is the "alert on
// unexpected blocked egress" metric turned into a finding.
func detectBlockedEgress(fl *FlowLog) []Anomaly {
	var out []Anomaly
	for _, d := range fl.Dests {
		if d.Denied == 0 {
			continue
		}
		out = append(out, Anomaly{
			Kind:     KindBlockedEg,
			Severity: engine.SeverityLow,
			Workload: fl.Workload.ID,
			Dest:     d.Host,
			Title:    "Egress denied by policy (blocked-egress alert)",
			Detail: fmt.Sprintf(
				"%d egress attempt(s) from %q to %s were dropped by policy. Repeated denials can indicate a misconfigured allowlist or a workload probing for an exit.",
				d.Denied, fl.Workload.ID, d.Host),
			Score: 0.5,
			Evidence: map[string]string{
				"denied":   fmt.Sprintf("%d", d.Denied),
				"dst_port": fmt.Sprintf("%d", d.Port),
			},
		})
	}
	return out
}

// sampleKeys returns up to n keys of a set in sorted order, for compact,
// deterministic evidence strings.
func sampleKeys(set map[string]bool, n int) string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > n {
		keys = keys[:n]
	}
	out := ""
	for i, k := range keys {
		if i > 0 {
			out += ","
		}
		out += k
	}
	return out
}
