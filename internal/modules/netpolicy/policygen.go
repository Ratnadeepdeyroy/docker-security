package netpolicy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/netmon"
)

// --- Least-privilege policy generation -----------------------------------
//
// Given one workload's observed baseline, synthesise the minimal egress policy
// that would still permit everything it actually did. We emit three artifacts:
//
//   * NetworkPolicy   — a standard Kubernetes egress policy (identity/label
//     selector, ipBlock + ports for IP destinations, always-allow DNS).
//   * FQDNAllowlist   — the DNS/FQDN allowlist for named destinations, which
//     standard NetworkPolicy cannot express (Cilium/Calico FQDN policy can).
//   * DefaultDeny     — the baseline "deny all egress" policy to apply first.
//
// Everything is advisory. Determinism: peers, ports, and domains are sorted, and
// when intent modelling is on, only "intended" destinations enter the allowlist
// (with the anomalous ones reported instead of silently permitted).

// Port is an L4 port/protocol pair in a generated rule.
type Port struct {
	Protocol string `json:"protocol"` // TCP or UDP
	Port     int    `json:"port"`
}

// EgressPeer is one allowed destination in a generated NetworkPolicy: either an
// ipBlock CIDR (external IP) or a namespace/pod label selector (internal peer).
type EgressPeer struct {
	CIDR            string            `json:"cidr,omitempty"`
	NamespaceLabels map[string]string `json:"namespace_labels,omitempty"`
	PodLabels       map[string]string `json:"pod_labels,omitempty"`
	Ports           []Port            `json:"ports,omitempty"`
}

// NetworkPolicy is a minimal, renderable Kubernetes NetworkPolicy. DefaultDeny
// marks the empty-egress "deny all" form.
type NetworkPolicy struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	PodSelector map[string]string `json:"pod_selector"`
	Egress      []EgressPeer      `json:"egress,omitempty"`
	DefaultDeny bool              `json:"default_deny"`
}

// FQDNEntry is one domain on the DNS/FQDN egress allowlist, with the class and
// rationale from intent modelling so a reviewer/agent sees *why* it is allowed.
type FQDNEntry struct {
	FQDN      string   `json:"fqdn"`
	Ports     []Port   `json:"ports,omitempty"`
	Class     string   `json:"class,omitempty"`     // intended | anomalous | observed
	Rationale []string `json:"rationale,omitempty"` // human+machine reasons
}

// GeneratedPolicy bundles the artifacts produced for one workload.
type GeneratedPolicy struct {
	Workload      string        `json:"workload"`
	Namespace     string        `json:"namespace"`
	Policy        NetworkPolicy `json:"policy"`
	DefaultDeny   NetworkPolicy `json:"default_deny"`
	FQDNAllowlist []FQDNEntry   `json:"fqdn_allowlist"`
	// Excluded lists destinations left OFF the allowlist because intent modelling
	// classed them anomalous — surfaced so the omission is explicit, not silent.
	Excluded []FQDNEntry `json:"excluded,omitempty"`
}

// GenOptions tunes generation.
type GenOptions struct {
	Namespace string
	// UseIntent, when set, restricts the allowlist to intended destinations and
	// records anomalous ones under Excluded. Off by default (mirrors netmon).
	UseIntent bool
	// Opts carries the netmon thresholds used for intent classification.
	Opts netmon.Options
}

// dnsPort is the always-allowed resolver egress; a pod that cannot resolve names
// is broken, so every generated policy permits DNS.
var dnsPorts = []Port{{Protocol: "UDP", Port: 53}, {Protocol: "TCP", Port: 53}}

// GeneratePolicy synthesises the least-privilege artifacts for one workload's
// observed flow log.
func GeneratePolicy(fl *netmon.FlowLog, g GenOptions) GeneratedPolicy {
	ns := g.Namespace
	if ns == "" {
		ns = fl.Workload.Namespace
	}
	if ns == "" {
		ns = "default"
	}
	selector := podSelector(fl.Workload)

	gp := GeneratedPolicy{
		Workload:  fl.Workload.ID,
		Namespace: ns,
		DefaultDeny: NetworkPolicy{
			Name:        "default-deny-egress",
			Namespace:   ns,
			PodSelector: map[string]string{}, // empty selector = all pods in ns
			DefaultDeny: true,
		},
		Policy: NetworkPolicy{
			Name:        "allow-egress-" + sanitizeName(fl.Workload.ID),
			Namespace:   ns,
			PodSelector: selector,
		},
	}

	// Intent classification (only used to gate the allowlist when enabled).
	class := map[string]netmon.EgressIntent{}
	if g.UseIntent {
		for _, in := range netmon.ClassifyEgress(fl, g.Opts) {
			class[in.Dest] = in
		}
	}

	// DNS egress is always permitted (to the cluster resolver).
	gp.Policy.Egress = append(gp.Policy.Egress, EgressPeer{
		NamespaceLabels: map[string]string{"kubernetes.io/metadata.name": "kube-system"},
		Ports:           dnsPorts,
	})

	seenCIDR := map[string]bool{}
	for _, d := range fl.Dests {
		if d.IMDS {
			continue // never auto-allow the metadata endpoint
		}
		port := Port{Protocol: protoFor(d.Proto), Port: int(d.Port)}

		// Intent gating (external dests only — ClassifyEgress ignores internal).
		// When on, an anomalous destination is recorded under Excluded and kept
		// OFF the least-privilege policy rather than silently permitted, whether
		// it is named or a raw IP.
		if g.UseIntent {
			if in, ok := class[d.Host]; ok && in.Class == netmon.ClassAnomalous {
				gp.Excluded = append(gp.Excluded, FQDNEntry{
					FQDN: d.Host, Ports: []Port{port}, Class: string(in.Class), Rationale: in.Reasons,
				})
				continue
			}
		}

		// Named external destination → FQDN allowlist.
		if d.FQDN != "" && !d.Internal {
			entry := FQDNEntry{FQDN: d.FQDN, Ports: []Port{port}, Class: "observed"}
			if g.UseIntent {
				if in, ok := class[d.Host]; ok {
					entry.Class = string(in.Class)
					entry.Rationale = in.Reasons
				}
			}
			gp.FQDNAllowlist = append(gp.FQDNAllowlist, entry)
			continue
		}

		// IP destination → ipBlock /32 (or /128) in the NetworkPolicy.
		if d.IP != "" {
			cidr := hostCIDR(d.IP)
			if cidr == "" || seenCIDR[cidr+portKey(port)] {
				continue
			}
			seenCIDR[cidr+portKey(port)] = true
			gp.Policy.Egress = append(gp.Policy.Egress, EgressPeer{
				CIDR:  cidr,
				Ports: []Port{port},
			})
		}
	}

	sortPolicy(&gp)
	return gp
}

// GenerateForCapture generates artifacts for every workload with egress in the
// capture, in stable workload order.
func GenerateForCapture(c *netmon.Capture, g GenOptions) []GeneratedPolicy {
	c.Normalize()
	var out []GeneratedPolicy
	for _, fl := range netmon.BuildFlowLogs(c) {
		if len(fl.Egress) == 0 {
			continue
		}
		out = append(out, GeneratePolicy(fl, g))
	}
	return out
}

// --- helpers -------------------------------------------------------------

// podSelector derives an identity-based (label) selector from the workload —
// the whole point of policy that follows a workload across reschedules. Falls
// back to a name label when the workload carries none.
func podSelector(w netmon.Workload) map[string]string {
	if len(w.Labels) > 0 {
		out := make(map[string]string, len(w.Labels))
		for k, v := range w.Labels {
			out[k] = v
		}
		return out
	}
	name := w.Name
	if name == "" {
		name = w.ID
	}
	return map[string]string{"app": sanitizeName(name)}
}

func protoFor(p netmon.Protocol) string {
	if p == netmon.ProtoUDP {
		return "UDP"
	}
	return "TCP"
}

// hostCIDR turns a single IP into a host CIDR (/32 for IPv4, /128 for IPv6).
func hostCIDR(ip string) string {
	if strings.Contains(ip, ":") {
		return ip + "/128"
	}
	if strings.Count(ip, ".") == 3 {
		return ip + "/32"
	}
	return ""
}

func portKey(p Port) string { return fmt.Sprintf("|%s/%d", p.Protocol, p.Port) }

// sanitizeName lowercases and strips characters not valid in a Kubernetes
// resource/label name so generated manifests apply cleanly.
func sanitizeName(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			b.WriteRune(r)
		case r == '/', r == '_', r == '.', r == ' ':
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "workload"
	}
	return out
}

// sortPolicy imposes deterministic ordering on every generated slice.
func sortPolicy(gp *GeneratedPolicy) {
	sort.SliceStable(gp.Policy.Egress, func(i, j int) bool {
		return egressPeerKey(gp.Policy.Egress[i]) < egressPeerKey(gp.Policy.Egress[j])
	})
	sort.SliceStable(gp.FQDNAllowlist, func(i, j int) bool { return gp.FQDNAllowlist[i].FQDN < gp.FQDNAllowlist[j].FQDN })
	sort.SliceStable(gp.Excluded, func(i, j int) bool { return gp.Excluded[i].FQDN < gp.Excluded[j].FQDN })
}

// egressPeerKey is a stable sort key for an egress peer.
func egressPeerKey(p EgressPeer) string {
	parts := []string{p.CIDR}
	for k, v := range p.NamespaceLabels {
		parts = append(parts, "ns:"+k+"="+v)
	}
	for k, v := range p.PodLabels {
		parts = append(parts, "pod:"+k+"="+v)
	}
	sort.Strings(parts)
	key := strings.Join(parts, ";")
	if len(p.Ports) > 0 {
		key += portKey(p.Ports[0])
	}
	return key
}
