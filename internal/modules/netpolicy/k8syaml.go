package netpolicy

import (
	"sort"
	"strings"
)

// --- Deterministic YAML rendering ----------------------------------------
//
// We hand-render YAML rather than pull in a dependency (stdlib-only rule). The
// output shape is small and fixed — a Kubernetes NetworkPolicy and our advisory
// FQDN allowlist — so a focused renderer is safer than a general marshaller and
// gives us exact control over key ordering (the key to deterministic goldens).

// yamlWriter accumulates indented YAML lines.
type yamlWriter struct {
	b strings.Builder
}

func (w *yamlWriter) line(indent int, s string) {
	for i := 0; i < indent; i++ {
		w.b.WriteString("  ")
	}
	w.b.WriteString(s)
	w.b.WriteByte('\n')
}

func (w *yamlWriter) String() string { return w.b.String() }

// RenderNetworkPolicy renders a NetworkPolicy as a valid Kubernetes manifest.
// The default-deny form emits an empty egress list (which Kubernetes interprets
// as "deny all egress" for the selected pods).
func RenderNetworkPolicy(p NetworkPolicy) string {
	w := &yamlWriter{}
	w.line(0, "apiVersion: networking.k8s.io/v1")
	w.line(0, "kind: NetworkPolicy")
	w.line(0, "metadata:")
	w.line(1, "name: "+yamlScalar(p.Name))
	w.line(1, "namespace: "+yamlScalar(p.Namespace))
	w.line(0, "spec:")
	renderSelector(w, 1, "podSelector", p.PodSelector)
	w.line(1, "policyTypes:")
	w.line(2, "- Egress")

	if p.DefaultDeny || len(p.Egress) == 0 {
		// No egress key at all == deny-all egress for the selected pods. We add a
		// clarifying comment so a human reviewer is not surprised by the absence.
		w.line(1, "# no egress rules: this denies all egress for the selected pods")
		return w.String()
	}

	w.line(1, "egress:")
	for _, peer := range p.Egress {
		renderEgressPeer(w, peer)
	}
	return w.String()
}

// renderSelector renders a matchLabels selector, or `{}` when empty (all pods).
func renderSelector(w *yamlWriter, indent int, field string, labels map[string]string) {
	if len(labels) == 0 {
		w.line(indent, field+": {}")
		return
	}
	w.line(indent, field+":")
	w.line(indent+1, "matchLabels:")
	for _, k := range sortedKeys(labels) {
		w.line(indent+2, yamlScalar(k)+": "+yamlScalar(labels[k]))
	}
}

// renderEgressPeer renders one egress list item (a `to` peer plus its ports).
// Indentation follows the standard Kubernetes NetworkPolicy shape: `ports` is a
// sibling key of `to` within the same list-item map, the `to` sequence sits one
// level under that map, and each selector's fields (ipBlock.cidr,
// namespaceSelector.matchLabels) nest one level under the selector key. The
// resulting manifest round-trips through a YAML parser (see the render golden).
func renderEgressPeer(w *yamlWriter, p EgressPeer) {
	w.line(2, "- to:")
	switch {
	case p.CIDR != "":
		w.line(4, "- ipBlock:")
		w.line(6, "cidr: "+yamlScalar(p.CIDR))
	case len(p.NamespaceLabels) > 0 || len(p.PodLabels) > 0:
		w.line(4, "- namespaceSelector:")
		if len(p.NamespaceLabels) > 0 {
			w.line(6, "matchLabels:")
			for _, k := range sortedKeys(p.NamespaceLabels) {
				w.line(7, yamlScalar(k)+": "+yamlScalar(p.NamespaceLabels[k]))
			}
		} else {
			w.line(6, "matchLabels: {}")
		}
		// A pod selector in the same peer ANDs with the namespace selector; it is
		// a sibling key of namespaceSelector (aligned under the list-item dash).
		if len(p.PodLabels) > 0 {
			w.line(5, "podSelector:")
			w.line(6, "matchLabels:")
			for _, k := range sortedKeys(p.PodLabels) {
				w.line(7, yamlScalar(k)+": "+yamlScalar(p.PodLabels[k]))
			}
		}
	}
	if len(p.Ports) > 0 {
		w.line(3, "ports:")
		for _, port := range p.Ports {
			w.line(4, "- protocol: "+port.Protocol)
			w.line(5, "port: "+itoa(port.Port))
		}
	}
}

// RenderFQDNAllowlist renders the DNS/FQDN egress allowlist as an advisory YAML
// document. Standard NetworkPolicy cannot express FQDN egress, so this is a
// portable artifact for an FQDN-aware CNI (Cilium toFQDNs, Calico DNS policy).
// Each entry carries its intent class and rationale as comments so a reviewer or
// agent can see why the domain is permitted.
func RenderFQDNAllowlist(gp GeneratedPolicy) string {
	w := &yamlWriter{}
	w.line(0, "# Advisory DNS/FQDN egress allowlist (generated from observed traffic).")
	w.line(0, "# Apply with an FQDN-aware policy engine (Cilium toFQDNs / Calico DNS policy).")
	w.line(0, "kind: FQDNEgressAllowlist")
	w.line(0, "workload: "+yamlScalar(gp.Workload))
	w.line(0, "namespace: "+yamlScalar(gp.Namespace))
	if len(gp.FQDNAllowlist) == 0 {
		w.line(0, "allow: []")
	} else {
		w.line(0, "allow:")
		for _, e := range gp.FQDNAllowlist {
			renderFQDNEntry(w, e)
		}
	}
	if len(gp.Excluded) > 0 {
		w.line(0, "# excluded (classified anomalous by intent modelling — review before allowing):")
		for _, e := range gp.Excluded {
			w.line(0, "#   - "+e.FQDN+"  ("+strings.Join(e.Rationale, "; ")+")")
		}
	}
	return w.String()
}

func renderFQDNEntry(w *yamlWriter, e FQDNEntry) {
	w.line(1, "- fqdn: "+yamlScalar(e.FQDN))
	if e.Class != "" {
		w.line(2, "class: "+yamlScalar(e.Class))
	}
	if len(e.Ports) > 0 {
		w.line(2, "ports:")
		for _, p := range e.Ports {
			w.line(3, "- protocol: "+p.Protocol)
			w.line(4, "port: "+itoa(p.Port))
		}
	}
	for _, r := range e.Rationale {
		w.line(2, "# "+r)
	}
}

// --- scalar helpers ------------------------------------------------------

// yamlScalar quotes a value only when YAML would otherwise misparse it, keeping
// output readable while staying valid.
func yamlScalar(s string) string {
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, ":{}[],&*#?|<>=!%@`\"'\n") || strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ") {
		return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return s
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// itoa is a tiny int→string without importing strconv into every call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
