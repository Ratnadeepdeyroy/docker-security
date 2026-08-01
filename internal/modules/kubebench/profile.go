package kubebench

import "strings"

// --- Version- and platform-matched profiles --------------------------------
//
// Two things vary between clusters: the CIS benchmark *revision* (tracks the
// Kubernetes minor version) and *who owns which controls* (on managed clusters
// the provider runs the control plane and etcd, so only node + policy controls
// are customer-scored). Profile captures both so the report is honest about
// what was assessed versus what the provider is responsible for.

// section names double as the control category used for profile scoping.
const (
	secControlPlane = "Control Plane"
	secEtcd         = "etcd"
	secNode         = "Worker Node"
	secPolicy       = "Policies"
)

// Profile is the resolved assessment scope for a cluster.
type Profile struct {
	// Name is the profile slug reported to the auditor, e.g. "self-managed",
	// "eks". It becomes the benchmark Profile field.
	Name string
	// BenchmarkVersion is the version-matched CIS Kubernetes Benchmark revision.
	BenchmarkVersion string
	// scored is the set of sections that are customer-owned and thus scored.
	// Sections outside this set report as INFO ("provider-managed").
	scored map[string]bool
}

// scores reports whether a control in the given section is customer-scored on
// this profile.
func (p Profile) scores(section string) bool { return p.scored[section] }

// selectProfile resolves the profile for the evidence: platform decides scope,
// version decides the benchmark revision. Detection is total — unknown inputs
// fall back to a full self-managed assessment against the newest known revision.
func selectProfile(e *Evidence) Profile {
	platform := strings.ToLower(strings.TrimSpace(e.Platform))
	version := benchmarkVersionFor(e.Version)

	allSections := map[string]bool{secControlPlane: true, secEtcd: true, secNode: true, secPolicy: true}
	managedSections := map[string]bool{secNode: true, secPolicy: true}

	switch platform {
	case "eks", "gke", "aks", "openshift":
		// Managed control plane + etcd are the provider's responsibility; only
		// node and policy controls are the customer's to score.
		return Profile{Name: platform, BenchmarkVersion: version, scored: managedSections}
	default:
		return Profile{Name: "self-managed", BenchmarkVersion: version, scored: allSections}
	}
}

// benchmarkVersionFor maps a Kubernetes server version onto the CIS Kubernetes
// Benchmark revision that targets it. The mapping follows CIS's published
// alignment (one benchmark revision tracks a small band of Kubernetes minors).
// An unrecognized/blank version resolves to the newest revision we ship.
func benchmarkVersionFor(k8s string) string {
	switch minorOf(k8s) {
	case 0:
		return "1.9.0" // unknown ⇒ newest shipped
	case 24, 25:
		return "1.7.0"
	case 26, 27:
		return "1.8.0"
	default: // 1.28+
		return "1.9.0"
	}
}

// minorOf extracts the Kubernetes minor version from a "1.29.3" / "v1.29" style
// string, returning 0 when it cannot be parsed.
func minorOf(v string) int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	if len(parts) < 2 {
		return 0
	}
	n := 0
	for _, r := range parts[1] {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}
