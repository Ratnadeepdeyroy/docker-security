package netpolicy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/netmon"
)

// --- Anomaly → Finding projection ----------------------------------------
//
// Each netmon anomaly kind maps to a stable DS-RAT-NET rule id and the standard
// references (MITRE ATT&CK technique ids, CIS, NIST) that let downstream tools
// and humans place the finding. Keeping the table in one place means adding a
// heuristic in netmon only needs one line here.

type ruleMeta struct {
	id         string
	references []string
}

var kindRules = map[netmon.AnomalyKind]ruleMeta{
	netmon.KindIMDS: {"DS-RAT-NET-010", []string{
		"https://attack.mitre.org/techniques/T1552/005/", // Cloud Instance Metadata API
		"https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-190.pdf",
	}},
	netmon.KindBeacon: {"DS-RAT-NET-011", []string{
		"https://attack.mitre.org/techniques/T1071/", // Application Layer Protocol
		"https://attack.mitre.org/techniques/T1571/", // Non-Standard Port
	}},
	netmon.KindExfil: {"DS-RAT-NET-012", []string{
		"https://attack.mitre.org/techniques/T1041/", // Exfiltration Over C2 Channel
		"https://attack.mitre.org/techniques/T1567/", // Exfiltration Over Web Service
	}},
	netmon.KindLowAndSlow: {"DS-RAT-NET-013", []string{
		"https://attack.mitre.org/techniques/T1030/", // Data Transfer Size Limits
	}},
	netmon.KindLateral: {"DS-RAT-NET-014", []string{
		"https://attack.mitre.org/tactics/TA0008/", // Lateral Movement
		"https://attack.mitre.org/techniques/T1021/",
	}},
	netmon.KindDNSTunnel: {"DS-RAT-NET-015", []string{
		"https://attack.mitre.org/techniques/T1071/004/", // DNS
		"https://attack.mitre.org/techniques/T1048/003/", // Exfil over unencrypted non-C2
	}},
	netmon.KindDGA: {"DS-RAT-NET-016", []string{
		"https://attack.mitre.org/techniques/T1568/002/", // Domain Generation Algorithms
	}},
	netmon.KindAgentEgress: {"DS-RAT-NET-020", []string{
		"https://attack.mitre.org/techniques/T1567/", // Exfiltration Over Web Service
		"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
	}},
	netmon.KindAnomalousEg: {"DS-RAT-NET-021", []string{
		"https://attack.mitre.org/tactics/TA0010/", // Exfiltration
	}},
	netmon.KindBlockedEg: {"DS-RAT-NET-030", []string{
		"https://kubernetes.io/docs/concepts/services-networking/network-policies/",
	}},
	netmon.KindHostNetwork: {"DS-RAT-NET-002", []string{
		"https://attack.mitre.org/techniques/T1610/", // Deploy Container
		"https://kubernetes.io/docs/concepts/security/pod-security-standards/",
	}},
	netmon.KindFreeForAll: {"DS-RAT-NET-003", []string{
		"https://kubernetes.io/docs/concepts/services-networking/network-policies/",
	}},
}

// anomalyToFinding projects a single netmon anomaly onto the unified Finding
// model, attaching the mapped rule id, references, and a remediation that points
// at the generator so an operator (or agent) can act on it.
func anomalyToFinding(a netmon.Anomaly) engine.Finding {
	meta, ok := kindRules[a.Kind]
	if !ok {
		meta = ruleMeta{id: "DS-RAT-NET-099"}
	}
	resource := a.Workload
	if a.Dest != "" {
		resource = a.Workload + " → " + a.Dest
	}
	ev := map[string]string{
		"kind":     string(a.Kind),
		"score":    fmt.Sprintf("%.3f", a.Score),
		"workload": a.Workload,
	}
	for k, v := range a.Evidence {
		ev[k] = v
	}
	return engine.Finding{
		RuleID:      meta.id,
		Module:      moduleName,
		Severity:    a.Severity,
		Title:       a.Title,
		Description: a.Detail,
		Resource:    resource,
		Remediation: remediationFor(a.Kind, a.Workload),
		References:  meta.references,
		Metadata:    ev,
	}
}

// remediationFor returns structured, model-consumable next steps per anomaly
// kind — the "explain & auto-remediate" thread from the innovation mandate.
func remediationFor(kind netmon.AnomalyKind, workload string) string {
	switch kind {
	case netmon.KindIMDS:
		return "Block egress to 169.254.169.254 for this workload and enforce IMDSv2 (hop-limit 1). Generate the deny with: dsecrat net <capture> --gen deny --workload " + workload
	case netmon.KindBeacon, netmon.KindExfil, netmon.KindLowAndSlow, netmon.KindDNSTunnel, netmon.KindDGA:
		return "Confirm the destination is legitimate; if not, isolate the workload and restrict egress to the generated least-privilege allowlist: dsecrat net <capture> --gen fqdn --workload " + workload
	case netmon.KindLateral:
		return "Apply identity/label-based east-west segmentation so this workload can only reach its known dependencies. Generate a NetworkPolicy: dsecrat net <capture> --gen policy --workload " + workload
	case netmon.KindAgentEgress:
		return "Add the destination to the agent's approved model/tool allowlist only after review; otherwise deny it. This is a potential data-exfiltration-via-model channel."
	case netmon.KindHostNetwork:
		return "Remove hostNetwork:true unless strictly required; host-networked pods bypass NetworkPolicy and cannot be egress-contained."
	default:
		return "Review the flow against the workload's intended egress baseline and add an explicit allow or deny rule."
	}
}

// --- Summary & posture findings ------------------------------------------

// summaryFinding is a gating-neutral INFO breadcrumb carrying the flow metrics
// the parity checklist asks for (counts, verdicts, bytes) so every analysed
// capture leaves a searchable record even when nothing else fired.
func summaryFinding(c *netmon.Capture, r *netmon.Report) engine.Finding {
	var egress, ingress, allow, deny int
	var bytesTx, bytesRx int64
	dests := map[string]bool{}
	for _, f := range c.Flows {
		switch f.Direction {
		case netmon.Ingress:
			ingress++
		default:
			egress++
			dests[f.Dst.FQDN+"|"+f.Dst.IP] = true
		}
		switch f.Verdict {
		case netmon.VerdictAllow:
			allow++
		case netmon.VerdictDeny:
			deny++
		}
		bytesTx += f.BytesTx
		bytesRx += f.BytesRx
	}
	return engine.Finding{
		RuleID:      "DS-RAT-NET-000",
		Module:      moduleName,
		Severity:    engine.SeverityInfo,
		Title:       fmt.Sprintf("Network capture analysed: %d workload(s), %d flow(s), %d anomaly(ies)", len(c.Workloads), len(c.Flows), len(r.Anomalies)),
		Description: fmt.Sprintf("policy_mode=%s egress=%d ingress=%d distinct_egress_dests=%d verdict_allow=%d verdict_deny=%d bytes_tx=%d bytes_rx=%d", policyModeOrNone(c.PolicyMode), egress, ingress, len(dests), allow, deny, bytesTx, bytesRx),
		Resource:    "network",
		References:  []string{"https://kubernetes.io/docs/concepts/services-networking/network-policies/"},
		Metadata: map[string]string{
			"workloads":    fmt.Sprintf("%d", len(c.Workloads)),
			"flows":        fmt.Sprintf("%d", len(c.Flows)),
			"anomalies":    fmt.Sprintf("%d", len(r.Anomalies)),
			"policy_mode":  policyModeOrNone(c.PolicyMode),
			"verdict_deny": fmt.Sprintf("%d", deny),
		},
	}
}

// postureFindings adds recommendations that are about the *shape* of the
// network rather than a single anomalous flow: default-deny egress and
// unrestricted east-west (inter-container free-for-all). Host-network is emitted
// by netmon per workload and mapped in anomalyToFinding, so it is not repeated
// here.
func postureFindings(c *netmon.Capture, r *netmon.Report) []engine.Finding {
	var out []engine.Finding

	// Default-deny egress: recommended whenever egress was observed without an
	// enforcing egress policy in place.
	if !enforcingEgress(c.PolicyMode) && hasEgress(c) {
		out = append(out, engine.Finding{
			RuleID:      "DS-RAT-NET-001",
			Module:      moduleName,
			Severity:    engine.SeverityMedium,
			Title:       "No default-deny egress policy in effect",
			Description: fmt.Sprintf("The capture ran with policy_mode=%q while workloads made outbound connections. Without a default-deny egress baseline, a compromised workload can reach any destination (C2, exfil, IMDS).", policyModeOrNone(c.PolicyMode)),
			Resource:    "cluster/egress",
			Remediation: "Apply a namespace-wide default-deny egress NetworkPolicy, then allow only observed destinations. Generate both with: dsecrat net <capture> --gen deny  and  dsecrat net <capture> --gen policy",
			References: []string{
				"https://kubernetes.io/docs/concepts/services-networking/network-policies/#default-deny-all-egress-traffic",
				"https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-190.pdf",
			},
			Metadata: map[string]string{"policy_mode": policyModeOrNone(c.PolicyMode)},
		})
	}

	// Inter-container free-for-all: multiple workloads reaching each other
	// east-west with nothing enforcing segmentation.
	if !enforcingEgress(c.PolicyMode) {
		if peers := eastWestPeers(r); len(peers) >= 2 {
			out = append(out, engine.Finding{
				RuleID:      "DS-RAT-NET-003",
				Module:      moduleName,
				Severity:    engine.SeverityLow,
				Title:       "Unrestricted inter-container (east-west) traffic",
				Description: fmt.Sprintf("%d workloads make internal peer-to-peer connections with no segmentation policy in effect. Flat east-west networking lets one compromised container pivot freely (CIS Docker: --icc=false; K8s: default-deny + explicit allows).", len(peers)),
				Resource:    "cluster/east-west",
				Remediation: "Disable free inter-container communication and apply identity/label-based segmentation so each workload reaches only its declared dependencies.",
				References: []string{
					"https://kubernetes.io/docs/concepts/services-networking/network-policies/",
				},
				Metadata: map[string]string{"east_west_workloads": strings.Join(peers, ",")},
			})
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

// eastWestPeers returns the sorted ids of workloads that made internal
// (private-range) egress connections.
func eastWestPeers(r *netmon.Report) []string {
	var ids []string
	for _, fl := range r.Logs {
		for _, d := range fl.Dests {
			if d.Internal && !d.IMDS {
				ids = append(ids, fl.Workload.ID)
				break
			}
		}
	}
	sort.Strings(ids)
	return ids
}

func hasEgress(c *netmon.Capture) bool {
	for _, f := range c.Flows {
		if f.Direction != netmon.Ingress {
			return true
		}
	}
	return false
}

func enforcingEgress(mode string) bool { return strings.EqualFold(strings.TrimSpace(mode), "enforce") }

func policyModeOrNone(mode string) string {
	if strings.TrimSpace(mode) == "" {
		return "none"
	}
	return mode
}
