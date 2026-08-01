// Package netmon is the offline core of Phase 6: network flow observability and
// egress analysis. It consumes recorded connection/DNS events (from a fixture
// today, from Phase-5 eBPF telemetry tomorrow — see Source), attributes each
// flow to a process+container+workload, aggregates per-workload flow logs, and
// runs deterministic detection heuristics (C2 beaconing, data exfiltration,
// lateral movement, cloud-metadata access, DNS tunnelling/DGA).
//
// It deliberately knows nothing about the CLI or HTTP frontends. The engine
// module in internal/modules/netpolicy adapts the anomalies and generated
// policies produced here onto the unified Finding model. The only shared
// dependency is engine.Severity, so an anomaly's risk speaks the same language
// as every other finding in the tool.
//
// Determinism is a hard requirement: nothing here reads the wall clock or a
// random source. Any notion of "now" is injected through Options, and every
// slice the package returns is sorted by a stable key. Same capture in, byte
// identical anomalies and policies out — that is what makes the golden tests
// meaningful and what lets an agent trust a generated allowlist.
package netmon

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

// --- Wire model ----------------------------------------------------------
//
// These types are the schema of a recorded capture (testdata/*.json) and the
// contract a telemetry source fills in. They are intentionally flat and
// JSON-friendly: telemetry arrives as a stream of events, and grouping into
// workloads happens later in FlowLog.

// Protocol is the L4 protocol of a flow.
type Protocol string

const (
	ProtoTCP  Protocol = "tcp"
	ProtoUDP  Protocol = "udp"
	ProtoICMP Protocol = "icmp"
)

// Direction is the flow direction relative to the attributed workload.
type Direction string

const (
	// Egress is workload-initiated traffic leaving the workload — the primary
	// concern for exfiltration, C2, and least-privilege egress policy.
	Egress Direction = "egress"
	// Ingress is traffic arriving at the workload.
	Ingress Direction = "ingress"
)

// Verdict records whether the dataplane allowed or dropped a flow. A capture
// taken in policy "audit" mode carries verdicts even when nothing is enforced,
// which is what lets us alert on unexpected drops (or unexpected allows).
type Verdict string

const (
	VerdictAllow   Verdict = "allow"
	VerdictDeny    Verdict = "deny"
	VerdictUnknown Verdict = ""
)

// Endpoint is one side of a flow. For an external destination IP and Port are
// set and FQDN is filled in when DNS correlation resolved the name; for an
// in-cluster peer Workload/Namespace identify it independently of its ephemeral
// IP (the whole point of identity-based policy).
type Endpoint struct {
	IP        string `json:"ip,omitempty"`
	Port      uint16 `json:"port,omitempty"`
	FQDN      string `json:"fqdn,omitempty"`
	Workload  string `json:"workload,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// key returns a stable string used for grouping and sorting endpoints. FQDN is
// preferred over IP so that ephemeral-IP churn does not fragment a destination.
func (e Endpoint) key() string {
	host := e.FQDN
	if host == "" {
		host = e.IP
	}
	return host + ":" + strconv.Itoa(int(e.Port))
}

// Flow is a single observed connection record, already attributed to the
// workload that opened it and the process inside that workload.
type Flow struct {
	// WorkloadID links the flow to a Workload in the same Capture.
	WorkloadID string    `json:"workload_id"`
	TSUnix     int64     `json:"ts_unix"`
	Proto      Protocol  `json:"proto"`
	Direction  Direction `json:"direction"`
	Src        Endpoint  `json:"src"`
	Dst        Endpoint  `json:"dst"`
	BytesTx    int64     `json:"bytes_tx"`
	BytesRx    int64     `json:"bytes_rx"`
	Verdict    Verdict   `json:"verdict,omitempty"`
	// Process attribution (the eBPF forensic correlation we get from Phase 5).
	Process string `json:"process,omitempty"`
	PID     int    `json:"pid,omitempty"`
}

// DNSEvent is a single resolver query/response, attributed to a workload. It is
// the raw material for tunnelling and DGA detection and for turning IP flows
// into FQDN egress allowlists.
type DNSEvent struct {
	WorkloadID string   `json:"workload_id"`
	TSUnix     int64    `json:"ts_unix"`
	QName      string   `json:"qname"`
	QType      string   `json:"qtype"`           // A, AAAA, TXT, NULL, ...
	RCode      string   `json:"rcode,omitempty"` // NOERROR, NXDOMAIN, ...
	Answers    []string `json:"answers,omitempty"`
}

// Workload is the identity a flow is attributed to. Kind carries an optional
// classification ("agent" marks an AI-agent workload, which the agent-egress
// governance feature keys off).
type Workload struct {
	ID          string            `json:"id"`
	Name        string            `json:"name,omitempty"`
	Namespace   string            `json:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Kind        string            `json:"kind,omitempty"`
	HostNetwork bool              `json:"host_network,omitempty"`
}

// Capture is a recorded window of network telemetry: the workloads seen and the
// flow and DNS events attributed to them. It is the unit a Source yields and
// the shape of every fixture under testdata/.
type Capture struct {
	// PolicyMode describes what egress enforcement was in place when the capture
	// was taken ("none", "audit", "enforce"). Absent means unknown/none, which is
	// itself worth flagging.
	PolicyMode string     `json:"policy_mode,omitempty"`
	Workloads  []Workload `json:"workloads"`
	Flows      []Flow     `json:"flows"`
	DNS        []DNSEvent `json:"dns,omitempty"`
}

// --- Normalisation -------------------------------------------------------

// Normalize sorts every slice in the capture into a canonical order so that two
// captures with the same events (in any input order) analyse identically. It is
// idempotent and safe to call more than once.
func (c *Capture) Normalize() {
	sort.SliceStable(c.Workloads, func(i, j int) bool { return c.Workloads[i].ID < c.Workloads[j].ID })
	sort.SliceStable(c.Flows, func(i, j int) bool { return flowLess(c.Flows[i], c.Flows[j]) })
	sort.SliceStable(c.DNS, func(i, j int) bool { return dnsLess(c.DNS[i], c.DNS[j]) })
}

func flowLess(a, b Flow) bool {
	if a.WorkloadID != b.WorkloadID {
		return a.WorkloadID < b.WorkloadID
	}
	if a.TSUnix != b.TSUnix {
		return a.TSUnix < b.TSUnix
	}
	if a.Dst.key() != b.Dst.key() {
		return a.Dst.key() < b.Dst.key()
	}
	return a.Src.key() < b.Src.key()
}

func dnsLess(a, b DNSEvent) bool {
	if a.WorkloadID != b.WorkloadID {
		return a.WorkloadID < b.WorkloadID
	}
	if a.TSUnix != b.TSUnix {
		return a.TSUnix < b.TSUnix
	}
	return a.QName < b.QName
}

// workloadIndex maps workload id to its descriptor for O(1) attribution lookup.
func (c *Capture) workloadIndex() map[string]Workload {
	idx := make(map[string]Workload, len(c.Workloads))
	for _, w := range c.Workloads {
		idx[w.ID] = w
	}
	return idx
}

// --- Address classification ----------------------------------------------
//
// Detection leans on "is this destination internal or out on the internet?".
// We answer that with the standard private/reserved ranges rather than a
// heuristic, so the boundary is well-defined and testable.

// imdsIPs are the cloud instance-metadata endpoints. Reaching any of these from
// a container is credential-theft-adjacent and always worth a finding.
var imdsIPs = map[string]bool{
	"169.254.169.254": true, // AWS/GCP/Azure/OpenStack IMDS
	"169.254.169.253": true, // AWS VPC DNS / secondary metadata
	"fd00:ec2::254":   true, // AWS IMDS over IPv6
	"100.100.100.200": true, // Alibaba Cloud metadata
}

// IsIMDS reports whether an IP is a known cloud metadata endpoint.
func IsIMDS(ip string) bool { return imdsIPs[strings.TrimSpace(ip)] }

// privateBlocks are the ranges we treat as "internal / east-west" for
// lateral-movement and internal-vs-external classification.
var privateBlocks = func() []*net.IPNet {
	cidrs := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC1918
		"100.64.0.0/10",  // CGNAT (common cluster pod CIDR overlap)
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local (includes IMDS; classified separately)
		"fc00::/7",       // IPv6 ULA
		"fe80::/10",      // IPv6 link-local
		"::1/128",        // IPv6 loopback
	}
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// IsInternal reports whether an IP falls in a private/reserved range. An
// unparseable or empty IP is treated as external so we never under-report
// egress to an unknown host.
func IsInternal(ip string) bool {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil {
		return false
	}
	for _, b := range privateBlocks {
		if b.Contains(p) {
			return true
		}
	}
	return false
}

// IsExternal reports whether an IP is a parseable, routable address outside the
// private/reserved ranges. An empty or unparseable string is not a valid
// external IP, so it returns false (the FQDN-only case is handled separately).
func IsExternal(ip string) bool {
	return net.ParseIP(strings.TrimSpace(ip)) != nil && !IsInternal(ip)
}
