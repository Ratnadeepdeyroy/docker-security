package runtime

import (
	"net"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// This file holds egress / command-and-control detection. The core signal is
// "this workload talked to an endpoint it should not have": a known-bad port, or
// — when an egress allowlist is configured — any endpoint outside it. IMDS theft
// is handled by DS-RAT-RT-005; this rule covers general C2 and exfiltration.

// --- DS-RAT-RT-007 C2 / egress anomaly ---------------------------------------

type egressRule struct {
	ruleBase
	allow *egressAllowlist
}

func newEgressRule(opts Options) Rule {
	return &egressRule{
		ruleBase: ruleBase{
			id: "DS-RAT-RT-007",
			info: RuleInfo{
				Title:       "Suspicious network egress (possible C2/exfiltration)",
				Severity:    engine.SeverityMedium,
				Technique:   techAppLayerC2,
				Default:     true,
				Description: "A container made an outbound connection that is suspicious: to a known command-and-control / remote-admin port, or — when an egress allowlist is configured — to an endpoint outside it. Beaconing to an unknown endpoint is the hallmark of an implant.",
				Remediation: "Apply default-deny egress NetworkPolicies and allowlist only required destinations. Investigate the destination reputation. Correlate with process drift (DS-RAT-RT-002) to confirm an implant.",
			},
		},
		allow: newEgressAllowlist(opts.EgressAllow),
	}
}

func (r *egressRule) Evaluate(ev *Event, st *State) []Detection {
	if ev.Kind != KindNetwork || ev.Network == nil {
		return nil
	}
	n := ev.Network
	// Only outbound connect attempts are C2-relevant.
	if n.Op != "connect" || (n.Direction != "" && n.Direction != "egress") {
		return nil
	}
	// IMDS is DS-RAT-RT-005's job; don't double-report here.
	if isIMDS(n) {
		return nil
	}

	// Signal 1: a known remote-admin / C2-favored port.
	if port, bad := suspiciousPort(n.RemotePort); bad {
		return []Detection{r.fire(ev, "egress to suspicious port "+port+" ("+endpointKey(n)+")",
			map[string]string{"endpoint": endpointKey(n), "reason": "suspicious-port"})}
	}

	// Signal 2: outside a configured egress allowlist (only when one is set).
	if r.allow.active() && !r.allow.permits(n) {
		// Fire on first contact with each novel endpoint to keep it quiet.
		if st.markConnect(containerKey(ev.Container)+"|egress", endpointKey(n)) {
			return []Detection{r.fire(ev, "egress to endpoint outside allowlist: "+endpointKey(n),
				map[string]string{"endpoint": endpointKey(n), "reason": "not-allowlisted"})}
		}
	}
	return nil
}

// suspiciousPort flags ports commonly used for remote shells / C2.
func suspiciousPort(p int) (string, bool) {
	switch p {
	case 4444, 1337, 31337, 6666, 6667, 12345, 9001, 5555:
		return itoa(p), true
	}
	return "", false
}

// --- Egress allowlist ----------------------------------------------------

// egressAllowlist matches connections against operator-provided known-good
// destinations. Entries may be domains (suffix match), IPs, or CIDRs. An empty
// allowlist is inactive — the rule then relies on hard signals only, never
// flooding on every connection.
type egressAllowlist struct {
	domains []string
	ips     map[string]struct{}
	cidrs   []*net.IPNet
}

func newEgressAllowlist(entries []string) *egressAllowlist {
	al := &egressAllowlist{ips: map[string]struct{}{}}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, cidr, err := net.ParseCIDR(e); err == nil {
			al.cidrs = append(al.cidrs, cidr)
			continue
		}
		if ip := net.ParseIP(e); ip != nil {
			al.ips[e] = struct{}{}
			continue
		}
		al.domains = append(al.domains, strings.ToLower(strings.TrimPrefix(e, ".")))
	}
	return al
}

func (a *egressAllowlist) active() bool {
	return a != nil && (len(a.domains) > 0 || len(a.ips) > 0 || len(a.cidrs) > 0)
}

// permits reports whether a connection targets an allowlisted destination.
func (a *egressAllowlist) permits(n *NetworkEvent) bool {
	if n.Domain != "" {
		d := strings.ToLower(n.Domain)
		for _, dom := range a.domains {
			if d == dom || strings.HasSuffix(d, "."+dom) {
				return true
			}
		}
	}
	if n.RemoteIP != "" {
		if _, ok := a.ips[n.RemoteIP]; ok {
			return true
		}
		if ip := net.ParseIP(n.RemoteIP); ip != nil {
			for _, c := range a.cidrs {
				if c.Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}
