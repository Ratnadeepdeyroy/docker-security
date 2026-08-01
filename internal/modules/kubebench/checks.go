package kubebench

import (
	"fmt"

	"github.com/Ratnadeepdeyroy/docker-security/internal/compliance"
)

// --- Check dispatch with profile scoping -----------------------------------

type checkFunc func(*Evidence) compliance.Assessment

// checkTable maps control id → check function. Controls with no entry are
// manual/informational.
func checkTable() map[string]checkFunc {
	return map[string]checkFunc{
		// Section 1 — control plane
		"1.1.1": check111APIServerPerms, "1.1.2": check112APIServerOwner,
		"1.2.1": check121AnonymousAuth, "1.2.2": check122TokenAuthFile,
		"1.2.6": check126AuthzNotAlwaysAllow, "1.2.7": check127AuthzNode, "1.2.8": check128AuthzRBAC,
		"1.2.11": check1211NoAlwaysAdmit, "1.2.16": check1216NodeRestriction,
		"1.2.19": check1219Profiling, "1.2.22": check1222AuditLog, "1.2.31": check1231Encryption,

		// Section 2 — etcd
		"2.1": check21EtcdServerTLS, "2.2": check22EtcdClientCertAuth, "2.3": check23EtcdAutoTLS,
		"2.4": check24EtcdPeerTLS, "2.5": check25EtcdPeerClientCertAuth, "2.6": check26EtcdPeerAutoTLS,

		// Section 4 — worker node
		"4.1.9": check419KubeletConfigPerms, "4.2.1": check421KubeletAnonAuth,
		"4.2.2": check422KubeletAuthz, "4.2.3": check423KubeletClientCA, "4.2.4": check424KubeletReadOnlyPort,
		"4.2.5": check425KubeletStreamingTimeout, "4.2.6": check426KubeletIPTables, "4.2.9": check429KubeletCertRotation,

		// Section 5 — policies
		"5.1.1": check511ClusterAdmin, "5.1.3": check513Wildcards, "5.1.5": check515DefaultSA,
		"5.2.2": check522PodSecurity, "5.3.2": check532NetworkPolicies, "5.7.4": check574DefaultNamespace,
	}
}

// assessorFor builds the profile-aware assessor. On managed clusters, controls
// in provider-owned sections (control plane, etcd) are reported as INFO with a
// clear "not customer-scored" note rather than a misleading fail/pass.
func assessorFor(e *Evidence, p Profile) compliance.Assessor {
	table := checkTable()
	return func(c compliance.Control) compliance.Assessment {
		if !p.scores(c.Section) {
			return compliance.Assessment{
				Status: compliance.StatusInfo,
				Evidence: fmt.Sprintf("%s controls are managed by the %s provider; not customer-scored",
					c.Section, p.Name),
			}
		}
		if fn, ok := table[c.ID]; ok {
			return fn(e)
		}
		return info("manual control; no automated check")
	}
}

// Assess resolves the profile from the evidence, then runs the version-matched
// CIS Kubernetes Benchmark. This is the single entry point for both the module
// and the `dsecrat bench k8s` command.
func Assess(e *Evidence) *compliance.Report {
	p := selectProfile(e)
	b := Benchmark(p)
	return b.Run(assessorFor(e, p))
}
