package netmon

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- AI-age features (off by default) ------------------------------------
//
// Two capabilities the incumbents do not ship, gated behind Options flags so the
// deterministic core never depends on them:
//
//   1. Egress intent modelling. Rather than dump a list of IPs for a human to
//      eyeball, cluster a workload's destinations into "intended" (the stable
//      baseline) and "anomalous" (rare/novel), each with a plain-language
//      rationale. That rationale is what lets an *agent* approve a generated
//      allowlist confidently instead of guessing.
//   2. Agent egress governance. AI-agent workloads phone home to model and tool
//      endpoints; "data exfiltration via a model API" is an emerging vector. We
//      specifically watch agent workloads and flag egress to model/inference
//      hosts that are not on the known-good list.

// EgressClass labels a destination's inferred intent.
type EgressClass string

const (
	// ClassIntended is a destination the workload contacts consistently — the
	// baseline that a least-privilege allowlist should permit.
	ClassIntended EgressClass = "intended"
	// ClassAnomalous is a rare, one-off, or otherwise unexpected destination that
	// warrants review before it enters an allowlist.
	ClassAnomalous EgressClass = "anomalous"
)

// EgressIntent is the classification of one destination, with a rationale that
// is both human-readable and machine-parseable (the reasons slice).
type EgressIntent struct {
	Dest       string
	Class      EgressClass
	Reasons    []string
	Count      int
	BytesTx    int64
	FQDN       string
	Confidence float64
}

// ClassifyEgress buckets a workload's external destinations into intended vs
// anomalous using deterministic, explainable rules (no model, no randomness).
// It is exported so both the intent detector and policy generation can reuse the
// same reasoning — an agent applying a policy sees exactly why each entry is on
// (or off) the allowlist. Results are sorted by destination for stability.
func ClassifyEgress(fl *FlowLog, o Options) []EgressIntent {
	o = o.withDefaults()
	var out []EgressIntent
	for _, d := range fl.ExternalDests() {
		if d.IMDS {
			continue // IMDS is never "intended"; its own detector owns it
		}
		intent := EgressIntent{Dest: d.Host, Count: d.Count, BytesTx: d.BytesTx, FQDN: d.FQDN}

		named := d.FQDN != ""
		steady := d.Count >= o.IntentMinCount
		switch {
		case named && steady:
			intent.Class = ClassIntended
			intent.Reasons = append(intent.Reasons,
				fmt.Sprintf("resolved name %q contacted %d times (>= baseline %d)", d.FQDN, d.Count, o.IntentMinCount))
			intent.Confidence = 0.9
		case named && !steady:
			intent.Class = ClassAnomalous
			intent.Reasons = append(intent.Reasons,
				fmt.Sprintf("named host but only %d contact(s) — below the baseline of %d, so novel/rare", d.Count, o.IntentMinCount))
			intent.Confidence = 0.6
		default:
			intent.Class = ClassAnomalous
			intent.Reasons = append(intent.Reasons, "destination is a raw IP with no resolved name (IP-literal egress is unusual for legitimate services)")
			intent.Confidence = 0.7
		}
		if isHighRiskPort(d.Port) {
			intent.Class = ClassAnomalous
			intent.Reasons = append(intent.Reasons, fmt.Sprintf("destination port %d is not a common egress service port", d.Port))
			if intent.Confidence < 0.7 {
				intent.Confidence = 0.7
			}
		}
		intent.Confidence = round3(intent.Confidence)
		out = append(out, intent)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Dest < out[j].Dest })
	return out
}

// detectAnomalousEgress turns the anomalous half of the intent model into
// findings. Only fires when Options.EnableIntent is set.
func detectAnomalousEgress(fl *FlowLog, o Options) []Anomaly {
	var out []Anomaly
	for _, in := range ClassifyEgress(fl, o) {
		if in.Class != ClassAnomalous {
			continue
		}
		out = append(out, Anomaly{
			Kind:     KindAnomalousEg,
			Severity: engine.SeverityLow,
			Workload: fl.Workload.ID,
			Dest:     in.Dest,
			Title:    "Anomalous egress destination (outside learned baseline)",
			Detail: fmt.Sprintf("Destination %s classified anomalous: %s.",
				in.Dest, strings.Join(in.Reasons, "; ")),
			Score: in.Confidence,
			Evidence: map[string]string{
				"class":      string(in.Class),
				"reasons":    strings.Join(in.Reasons, " | "),
				"contacts":   fmt.Sprintf("%d", in.Count),
				"confidence": fmt.Sprintf("%.3f", in.Confidence),
			},
		})
	}
	return out
}

// knownModelHosts are widely-used LLM/inference and agent-tool endpoints. Egress
// to these from an agent workload is expected; egress to a model-looking host
// NOT on this list is what we flag. Kept as suffixes so subdomains match.
var knownModelHosts = []string{
	"api.openai.com",
	"api.anthropic.com",
	"generativelanguage.googleapis.com",
	"api.cohere.ai",
	"api.mistral.ai",
	"api.groq.com",
	"bedrock-runtime.amazonaws.com",
	"openai.azure.com",
	"huggingface.co",
	"api-inference.huggingface.co",
}

// modelHostHints are tokens that make a hostname *look* like an inference
// endpoint. An unknown host matching one of these from an agent workload is the
// data-exfil-via-model case worth surfacing.
var modelHostHints = []string{"llm", "gpt", "inference", "ml-", "ai-", ".ai", "model", "embedding", "completion"}

// isKnownModelHost reports whether host is (a subdomain of) a known model host.
func isKnownModelHost(host string) bool {
	host = strings.ToLower(host)
	for _, k := range knownModelHosts {
		if host == k || strings.HasSuffix(host, "."+k) || strings.HasSuffix(host, k) {
			return true
		}
	}
	return false
}

// looksLikeModelHost reports whether an unknown host resembles an inference
// endpoint by name.
func looksLikeModelHost(host string) bool {
	host = strings.ToLower(host)
	for _, h := range modelHostHints {
		if strings.Contains(host, h) {
			return true
		}
	}
	return false
}

// isAgentWorkload reports whether a workload is an AI agent, by explicit Kind or
// by a conventional label. Governance only scrutinises agent workloads so we do
// not spam ordinary services with model-egress findings.
func isAgentWorkload(w Workload) bool {
	if strings.EqualFold(w.Kind, "agent") || strings.EqualFold(w.Kind, "ai-agent") {
		return true
	}
	for k, v := range w.Labels {
		lk, lv := strings.ToLower(k), strings.ToLower(v)
		if (lk == "app.kubernetes.io/component" && lv == "agent") ||
			(lk == "workload-type" && (lv == "agent" || lv == "ai-agent")) {
			return true
		}
	}
	return false
}

// detectAgentEgress flags AI-agent workloads reaching model/inference hosts that
// are not on the known-good list. Only fires when Options.EnableAgentEgress is
// set. Severity is raised when the unknown host itself looks like an inference
// endpoint (a plausible exfil-via-model channel).
func detectAgentEgress(fl *FlowLog) []Anomaly {
	if !isAgentWorkload(fl.Workload) {
		return nil
	}
	var out []Anomaly
	for _, d := range fl.ExternalDests() {
		if d.IMDS {
			continue
		}
		host := d.Host
		if isKnownModelHost(host) {
			continue // expected model endpoint for an agent
		}
		looksModel := looksLikeModelHost(host)
		sev := engine.SeverityMedium
		title := "AI-agent egress to non-allowlisted external host"
		if looksModel {
			sev = engine.SeverityHigh
			title = "AI-agent egress to unknown LLM/inference host (possible exfil-via-model)"
		}
		reason := "destination is not on the known model/tool allowlist"
		if looksModel {
			reason = "destination name resembles an LLM/inference endpoint but is not on the known-good allowlist — data-exfiltration-via-model risk"
		}
		out = append(out, Anomaly{
			Kind:     KindAgentEgress,
			Severity: sev,
			Workload: fl.Workload.ID,
			Dest:     host,
			Title:    title,
			Detail: fmt.Sprintf("Agent workload %q sent %s to %s across %d connection(s); %s.",
				fl.Workload.ID, humanBytes(d.BytesTx), host, d.Count, reason),
			Score: 0.8,
			Evidence: map[string]string{
				"looks_like_model": fmt.Sprintf("%t", looksModel),
				"bytes_tx":         fmt.Sprintf("%d", d.BytesTx),
				"connections":      fmt.Sprintf("%d", d.Count),
			},
		})
	}
	return out
}

// isHighRiskPort reports whether a destination port is outside the common
// egress service set (HTTP/S, DNS, common DBs). Egress on an odd port is a mild
// anomaly signal for intent classification.
func isHighRiskPort(p uint16) bool {
	switch p {
	case 0, 53, 80, 123, 443, 587, 993, 995, 5432, 3306, 6379, 27017, 8080, 8443:
		return false
	default:
		return true
	}
}
