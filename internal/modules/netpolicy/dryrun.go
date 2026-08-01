package netpolicy

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/netmon"
)

// --- Policy dry-run / audit ----------------------------------------------
//
// Before you enforce a policy you want to know what it would break. DryRun takes
// a candidate allowlist and replays a recorded capture against it, reporting
// exactly which egress flows would be denied — the "staged/audit policy" pattern
// that lets you validate rules without dropping real traffic. Run the generated
// policy's own allowlist against its baseline and you get the proof the phase
// DoD asks for: the generated policy admits the observed baseline (only IMDS,
// which we deliberately never allow, shows as denied).

// Allowlist is a candidate egress policy expressed as matchable rules. It is the
// JSON shape the `--dry-run` flag consumes and the shape AllowlistFromPolicy
// produces from a generated policy.
type Allowlist struct {
	// FQDNs are permitted destination names; a leading "." or bare domain matches
	// subdomains too (".example.com" and "example.com" both match "a.example.com").
	FQDNs []string `json:"fqdns,omitempty"`
	// CIDRs are permitted destination IP ranges.
	CIDRs []string `json:"cidrs,omitempty"`
	// Ports restricts allowed destination ports; empty means any port.
	Ports []int `json:"ports,omitempty"`
	// AllowInternal permits all private-range (east-west) egress.
	AllowInternal bool `json:"allow_internal,omitempty"`
	// AllowDNS permits UDP/TCP 53 to any resolver (a pod must resolve names).
	AllowDNS bool `json:"allow_dns,omitempty"`
}

// DeniedFlow is one destination a candidate policy would drop, aggregated over
// the connections to it.
type DeniedFlow struct {
	Workload string `json:"workload"`
	Dest     string `json:"dest"`
	IP       string `json:"ip,omitempty"`
	Port     uint16 `json:"port"`
	Count    int    `json:"count"`
	Reason   string `json:"reason"`
}

// DryRunResult is the outcome of auditing a capture against a candidate policy.
type DryRunResult struct {
	AllowedDests int          `json:"allowed_dests"`
	DeniedDests  int          `json:"denied_dests"`
	Denied       []DeniedFlow `json:"denied"`
}

// DecodeAllowlist parses a candidate Allowlist from JSON.
func DecodeAllowlist(r io.Reader) (Allowlist, error) {
	var a Allowlist
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return Allowlist{}, fmt.Errorf("decode allowlist: %w", err)
	}
	return a, nil
}

// AllowlistFromPolicy derives the matchable allowlist implied by a generated
// policy: its FQDN entries, its ipBlock CIDRs, and DNS egress. Used to prove a
// generated policy against its own baseline.
func AllowlistFromPolicy(gp GeneratedPolicy) Allowlist {
	a := Allowlist{AllowDNS: true}
	for _, e := range gp.FQDNAllowlist {
		a.FQDNs = append(a.FQDNs, e.FQDN)
	}
	// Internal peers are rendered as ipBlock CIDRs (the IP branch of generation),
	// so a CIDR match covers them. We deliberately do NOT infer AllowInternal
	// from the always-present DNS namespaceSelector rule — that would widen the
	// allowlist to all east-west traffic, defeating least privilege.
	for _, peer := range gp.Policy.Egress {
		if peer.CIDR != "" {
			a.CIDRs = append(a.CIDRs, peer.CIDR)
		}
	}
	sort.Strings(a.FQDNs)
	sort.Strings(a.CIDRs)
	return a
}

// DryRun replays a capture against a candidate allowlist and returns the
// would-be-denied destinations in deterministic order.
func DryRun(c *netmon.Capture, a Allowlist) DryRunResult {
	c.Normalize()
	nets := parseCIDRs(a.CIDRs)
	ports := intSet(a.Ports)

	var res DryRunResult
	for _, fl := range netmon.BuildFlowLogs(c) {
		for _, d := range fl.Dests {
			if permits(a, nets, ports, d) {
				res.AllowedDests++
				continue
			}
			res.Denied = append(res.Denied, DeniedFlow{
				Workload: fl.Workload.ID,
				Dest:     d.Host,
				IP:       d.IP,
				Port:     d.Port,
				Count:    d.Count,
				Reason:   denyReason(a, d),
			})
		}
	}
	res.DeniedDests = len(res.Denied)
	sort.SliceStable(res.Denied, func(i, j int) bool {
		if res.Denied[i].Workload != res.Denied[j].Workload {
			return res.Denied[i].Workload < res.Denied[j].Workload
		}
		return res.Denied[i].Dest < res.Denied[j].Dest
	})
	return res
}

// permits reports whether a destination clears the candidate allowlist.
func permits(a Allowlist, nets []*net.IPNet, ports map[int]bool, d *netmon.DestStat) bool {
	// DNS is a special-case always-needed egress.
	if a.AllowDNS && (d.Port == 53) {
		return true
	}
	if !portAllowed(ports, d.Port) {
		return false
	}
	// Internal east-west, if permitted wholesale.
	if d.Internal && a.AllowInternal {
		return true
	}
	// FQDN match (suffix-aware).
	if d.FQDN != "" && fqdnAllowed(a.FQDNs, d.FQDN) {
		return true
	}
	// CIDR match.
	if d.IP != "" {
		ip := net.ParseIP(d.IP)
		for _, n := range nets {
			if ip != nil && n.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// denyReason explains, for a denied destination, the most specific cause — so a
// human or agent reading the audit knows what to add.
func denyReason(a Allowlist, d *netmon.DestStat) string {
	if d.IMDS {
		return "destination is the cloud metadata endpoint (never allowlisted by policy)"
	}
	if !portAllowed(intSet(a.Ports), d.Port) {
		return fmt.Sprintf("port %d not in allowed ports", d.Port)
	}
	if d.FQDN != "" {
		return fmt.Sprintf("fqdn %q not on allowlist", d.FQDN)
	}
	if d.Internal {
		return "internal peer and allow_internal is false"
	}
	return fmt.Sprintf("ip %s not in any allowed CIDR", d.IP)
}

func portAllowed(ports map[int]bool, p uint16) bool {
	if len(ports) == 0 {
		return true // empty means any port
	}
	return ports[int(p)]
}

// fqdnAllowed reports whether name is permitted by the allowlist, matching a
// domain and its subdomains.
func fqdnAllowed(list []string, name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, entry := range list {
		e := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(entry, "."), "."))
		if name == e || strings.HasSuffix(name, "."+e) {
			return true
		}
	}
	return false
}

func parseCIDRs(cidrs []string) []*net.IPNet {
	var out []*net.IPNet
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func intSet(xs []int) map[int]bool {
	if len(xs) == 0 {
		return nil
	}
	m := make(map[int]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}
