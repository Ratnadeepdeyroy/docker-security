package netmon

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- DNS tunnelling & DGA ------------------------------------------------
//
// DNS is a covert channel hiding in plain sight: resolvers are almost never
// blocked, so malware smuggles data out in query names (tunnelling) and locates
// live C2 via algorithmically generated domains (DGA). Two independent signals:
//
//   * Tunnelling — many queries under one parent domain, with long, high-entropy
//     subdomain labels and data-carrying record types (TXT/NULL/CNAME). The data
//     is the label; the label looks like base32/base64, i.e. high entropy.
//   * DGA — a burst of NXDOMAIN answers to high-entropy names as the malware
//     walks its generated list looking for the one the operator registered.
//
// Entropy is Shannon entropy in bits per character; English-ish hostnames sit
// well below the base32/base64 range that encoded data occupies.

// shannonEntropy returns the per-character Shannon entropy (bits) of s. Higher
// means less predictable; random/encoded strings approach log2(alphabet size).
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// parentDomain approximates the registrable domain as the rightmost two labels.
// Without a public-suffix list this over-groups a few multi-part TLDs (e.g.
// co.uk), but for detection it only needs to be stable and to cluster a
// tunnel's many subdomains under one key — which two-label grouping does.
func parentDomain(qname string) string {
	q := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(qname)), ".")
	labels := strings.Split(q, ".")
	if len(labels) <= 2 {
		return q
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// subLabels returns the portion of qname left of the parent domain — the part
// an attacker controls and stuffs data into.
func subLabels(qname, parent string) string {
	q := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(qname)), ".")
	return strings.TrimSuffix(strings.TrimSuffix(q, parent), ".")
}

// dataRecordType reports whether a query type is one commonly abused to carry
// tunnelled payloads back to the client.
func dataRecordType(qtype string) bool {
	switch strings.ToUpper(qtype) {
	case "TXT", "NULL", "CNAME", "AAAA":
		return true
	default:
		return false
	}
}

// detectDNS runs both DNS heuristics for a workload.
func detectDNS(fl *FlowLog, o Options) []Anomaly {
	if len(fl.DNS) == 0 {
		return nil
	}
	var out []Anomaly
	out = append(out, detectDNSTunnel(fl, o)...)
	if a, ok := detectDGA(fl, o); ok {
		out = append(out, a)
	}
	return out
}

// detectDNSTunnel groups a workload's queries by parent domain and flags any
// parent that receives many high-entropy, long-label lookups.
func detectDNSTunnel(fl *FlowLog, o Options) []Anomaly {
	type acc struct {
		count       int
		dataRecords int
		sumEntropy  float64
		sumLen      int
		maxLen      int
	}
	byParent := map[string]*acc{}
	for _, ev := range fl.DNS {
		p := parentDomain(ev.QName)
		a := byParent[p]
		if a == nil {
			a = &acc{}
			byParent[p] = a
		}
		sub := subLabels(ev.QName, p)
		a.count++
		a.sumEntropy += shannonEntropy(sub)
		a.sumLen += len(sub)
		if len(sub) > a.maxLen {
			a.maxLen = len(sub)
		}
		if dataRecordType(ev.QType) {
			a.dataRecords++
		}
	}

	parents := make([]string, 0, len(byParent))
	for p := range byParent {
		parents = append(parents, p)
	}
	sort.Strings(parents)

	var out []Anomaly
	for _, p := range parents {
		a := byParent[p]
		if a.count < o.DNSTunnelMinQueries {
			continue
		}
		avgEntropy := a.sumEntropy / float64(a.count)
		avgLen := float64(a.sumLen) / float64(a.count)
		// The label must actually look like encoded data: high entropy AND long.
		if avgEntropy < o.DNSEntropyThreshold || avgLen < 12 {
			continue
		}
		out = append(out, Anomaly{
			Kind:     KindDNSTunnel,
			Severity: engine.SeverityHigh,
			Workload: fl.Workload.ID,
			Dest:     p,
			Title:    "Probable DNS tunnelling (high-entropy subdomain queries)",
			Detail: fmt.Sprintf(
				"%d queries under %q with avg subdomain entropy %.2f bits/char and avg length %.0f (max %d); %d used data-carrying record types. Long, high-entropy labels under one parent are the signature of DNS tunnelling.",
				a.count, p, avgEntropy, avgLen, a.maxLen, a.dataRecords),
			Score: round3(math.Min(1, avgEntropy/4.0)),
			Evidence: map[string]string{
				"parent":       p,
				"queries":      fmt.Sprintf("%d", a.count),
				"avg_entropy":  fmt.Sprintf("%.2f", avgEntropy),
				"avg_sub_len":  fmt.Sprintf("%.0f", avgLen),
				"data_records": fmt.Sprintf("%d", a.dataRecords),
			},
		})
	}
	return out
}

// detectDGA flags a burst of failed lookups (NXDOMAIN) to high-entropy names —
// malware cycling through its generated domain list for the live rendezvous.
func detectDGA(fl *FlowLog, o Options) (Anomaly, bool) {
	var nx int
	var sumEntropy float64
	var entropySamples int
	nxDomains := map[string]bool{}
	for _, ev := range fl.DNS {
		if !strings.EqualFold(ev.RCode, "NXDOMAIN") {
			continue
		}
		nx++
		nxDomains[parentDomain(ev.QName)] = true
		// Entropy of the leftmost label — the generated part.
		labels := strings.Split(strings.TrimSuffix(strings.ToLower(ev.QName), "."), ".")
		if len(labels) > 0 {
			sumEntropy += shannonEntropy(labels[0])
			entropySamples++
		}
	}
	if nx < o.DGAMinNXDomain || entropySamples == 0 {
		return Anomaly{}, false
	}
	avgEntropy := sumEntropy / float64(entropySamples)
	if avgEntropy < o.DNSEntropyThreshold {
		return Anomaly{}, false
	}
	return Anomaly{
		Kind:     KindDGA,
		Severity: engine.SeverityHigh,
		Workload: fl.Workload.ID,
		Title:    "Probable DGA activity (NXDOMAIN storm to high-entropy domains)",
		Detail: fmt.Sprintf(
			"%d NXDOMAIN responses across %d distinct parent domains with avg leftmost-label entropy %.2f bits/char — the pattern of a domain-generation algorithm probing for its live C2 rendezvous.",
			nx, len(nxDomains), avgEntropy),
		Score: round3(math.Min(1, avgEntropy/4.0)),
		Evidence: map[string]string{
			"nxdomain_count":   fmt.Sprintf("%d", nx),
			"distinct_parents": fmt.Sprintf("%d", len(nxDomains)),
			"avg_entropy":      fmt.Sprintf("%.2f", avgEntropy),
		},
	}, true
}
