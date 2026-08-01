package netmon

import (
	"fmt"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Cloud instance-metadata access --------------------------------------

// detectIMDS flags any egress to a cloud metadata endpoint. This is one of the
// highest-signal container-escape indicators there is: a workload reaching
// 169.254.169.254 is almost always after node IAM credentials (SSRF pivot or
// post-exploitation), and legitimate apps rarely need it. We report per
// destination so the finding names exactly which metadata IP was touched.
func detectIMDS(fl *FlowLog) []Anomaly {
	var out []Anomaly
	for _, d := range fl.Dests {
		if !d.IMDS {
			continue
		}
		out = append(out, Anomaly{
			Kind:     KindIMDS,
			Severity: engine.SeverityCritical,
			Workload: fl.Workload.ID,
			Dest:     d.Host,
			Title:    "Egress to cloud instance-metadata endpoint (IMDS)",
			Detail: fmt.Sprintf(
				"Workload %q connected to metadata endpoint %s %d time(s). This endpoint vends node/instance IAM credentials; container access to it is a common credential-theft and privilege-escalation path.",
				fl.Workload.ID, d.Host, d.Count),
			Score: 1.0,
			Evidence: map[string]string{
				"dst_ip":      d.IP,
				"dst_port":    fmt.Sprintf("%d", d.Port),
				"connections": fmt.Sprintf("%d", d.Count),
			},
		})
	}
	return out
}
