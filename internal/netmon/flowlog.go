package netmon

import "sort"

// --- Per-workload flow logs ----------------------------------------------
//
// Detection and policy generation both work per workload: a beacon, a baseline,
// a generated NetworkPolicy — all are scoped to one workload's identity. FlowLog
// is that grouping. Building it once and handing the same structure to every
// detector keeps the heuristics small and avoids re-walking the raw capture.

// FlowLog is one workload's attributed traffic, split into destinations for
// egress analysis. It is the searchable per-flow view the market-parity
// checklist asks for (src/dst identity, port, verdict), grouped for reuse.
type FlowLog struct {
	Workload Workload
	Egress   []Flow
	Ingress  []Flow
	DNS      []DNSEvent
	// Dests aggregates egress by destination (FQDN-preferred key) in stable order.
	Dests []*DestStat
}

// DestStat rolls up every egress flow to a single logical destination. It is
// the unit beaconing/exfil reason over and the unit a policy allow-rule maps to.
type DestStat struct {
	Key        string // FQDN:port when known, else IP:port
	Host       string // FQDN if known else IP
	FQDN       string
	IP         string
	Port       uint16
	Proto      Protocol
	Internal   bool
	IMDS       bool
	Count      int
	BytesTx    int64
	BytesRx    int64
	FirstTS    int64
	LastTS     int64
	Denied     int     // flows with a deny verdict
	Timestamps []int64 // per-connection timestamps, ascending — beaconing input
}

// BuildFlowLogs groups a normalized capture into per-workload flow logs, sorted
// by workload id. A flow whose WorkloadID has no matching Workload descriptor is
// still attributed under a synthesized identity so telemetry gaps never drop
// coverage.
func BuildFlowLogs(c *Capture) []*FlowLog {
	idx := c.workloadIndex()
	logs := map[string]*FlowLog{}

	get := func(id string) *FlowLog {
		fl, ok := logs[id]
		if !ok {
			w, known := idx[id]
			if !known {
				w = Workload{ID: id, Name: id}
			}
			fl = &FlowLog{Workload: w}
			logs[id] = fl
		}
		return fl
	}

	for _, f := range c.Flows {
		fl := get(f.WorkloadID)
		if f.Direction == Ingress {
			fl.Ingress = append(fl.Ingress, f)
			continue
		}
		fl.Egress = append(fl.Egress, f)
	}
	for _, d := range c.DNS {
		fl := get(d.WorkloadID)
		fl.DNS = append(fl.DNS, d)
	}

	// Include workloads that appear only in the descriptor list (seen, but with
	// no recorded flows) so a host-network flag or "silent" workload is not lost.
	for _, w := range c.Workloads {
		if _, ok := logs[w.ID]; !ok {
			logs[w.ID] = &FlowLog{Workload: w}
		}
	}

	out := make([]*FlowLog, 0, len(logs))
	for _, fl := range logs {
		fl.aggregate()
		out = append(out, fl)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Workload.ID < out[j].Workload.ID })
	return out
}

// aggregate rolls this log's egress flows up into per-destination DestStats in
// deterministic (key) order. Called once during BuildFlowLogs.
func (fl *FlowLog) aggregate() {
	byKey := map[string]*DestStat{}
	for _, f := range fl.Egress {
		ds, ok := byKey[f.Dst.key()]
		if !ok {
			ip := f.Dst.IP
			ds = &DestStat{
				Key:      f.Dst.key(),
				Host:     hostOf(f.Dst),
				FQDN:     f.Dst.FQDN,
				IP:       ip,
				Port:     f.Dst.Port,
				Proto:    f.Proto,
				Internal: IsInternal(ip),
				IMDS:     IsIMDS(ip),
				FirstTS:  f.TSUnix,
				LastTS:   f.TSUnix,
			}
			byKey[f.Dst.key()] = ds
		}
		ds.Count++
		ds.BytesTx += f.BytesTx
		ds.BytesRx += f.BytesRx
		if f.TSUnix < ds.FirstTS {
			ds.FirstTS = f.TSUnix
		}
		if f.TSUnix > ds.LastTS {
			ds.LastTS = f.TSUnix
		}
		if f.Verdict == VerdictDeny {
			ds.Denied++
		}
		ds.Timestamps = append(ds.Timestamps, f.TSUnix)
	}

	fl.Dests = make([]*DestStat, 0, len(byKey))
	for _, ds := range byKey {
		sort.Slice(ds.Timestamps, func(i, j int) bool { return ds.Timestamps[i] < ds.Timestamps[j] })
		fl.Dests = append(fl.Dests, ds)
	}
	sort.SliceStable(fl.Dests, func(i, j int) bool { return fl.Dests[i].Key < fl.Dests[j].Key })
}

// hostOf returns the most identifying host label for an endpoint.
func hostOf(e Endpoint) string {
	switch {
	case e.FQDN != "":
		return e.FQDN
	case e.Workload != "":
		return e.Workload
	default:
		return e.IP
	}
}

// ExternalDests returns the routable-internet destinations in stable order —
// the set egress policy and exfil detection care about.
func (fl *FlowLog) ExternalDests() []*DestStat {
	var out []*DestStat
	for _, d := range fl.Dests {
		if d.IMDS || (!d.Internal && d.IP != "") || (d.IP == "" && d.FQDN != "") {
			out = append(out, d)
		}
	}
	return out
}
