package dockerbench

import "github.com/Ratnadeepdeyroy/docker-security/internal/compliance"

// benchmarkVersion is the CIS Docker Benchmark revision this catalogue targets.
// Recorded in the report so an auditor knows exactly which baseline was applied.
const benchmarkVersion = "1.6.0"

// --- framework-mapping shorthands ------------------------------------------
//
// Every control maps to CIS natively plus at least one other framework, so one
// scan feeds many audits. These keep the catalogue below readable.

func nist190(id string) compliance.FrameworkRef {
	return compliance.Ref(compliance.FrameworkNIST190, id)
}
func nist53(id string) compliance.FrameworkRef { return compliance.Ref(compliance.FrameworkNIST53, id) }
func stig(id string) compliance.FrameworkRef   { return compliance.Ref(compliance.FrameworkSTIG, id) }
func pci(id string) compliance.FrameworkRef    { return compliance.Ref(compliance.FrameworkPCI, id) }

// daemonFix builds an agent-appliable daemon.json remediation bundle.
func daemonFix(snippet, dryRun string) *compliance.Fix {
	return &compliance.Fix{Kind: "daemon.json", Target: "/etc/docker/daemon.json", Snippet: snippet, DryRun: dryRun}
}

// Benchmark returns the CIS Docker Benchmark control catalogue. It is pure data:
// the pass/fail logic lives in the check functions (daemon.go, files.go,
// runtime.go), keyed by control ID. Controls are authored grouped by section;
// the runner re-sorts them into stable numeric order.
func Benchmark() compliance.Benchmark {
	return compliance.Benchmark{
		Code:     "docker",
		Name:     "CIS Docker Benchmark",
		Version:  benchmarkVersion,
		Profile:  "self-managed",
		Controls: append(append(append(hostControls(), daemonControls()...), fileControls()...), runtimeControls()...),
	}
}

const (
	secHost    = "Host Configuration"
	secDaemon  = "Docker Daemon Configuration"
	secFiles   = "Docker Daemon Configuration Files"
	secRuntime = "Container Runtime"
)

// --- Section 1: Host Configuration -----------------------------------------

func hostControls() []compliance.Control {
	return []compliance.Control{{
		ID:      "1.2.1",
		Title:   "Ensure the container host has been hardened",
		Section: secHost,
		Level:   compliance.Level1,
		Scored:  false, // host hardening is broad; flagged for manual attestation
		Description: "The underlying host OS should follow an established hardening baseline; " +
			"a soft host undermines every daemon-level control above it.",
		Remediation: "Apply a host hardening baseline (CIS OS benchmark / DISA STIG) and record attestation.",
		Frameworks:  []compliance.FrameworkRef{nist190("4.5"), nist53("CM-6"), stig("SRG-APP-000516")},
	}}
}

// --- Section 2: Docker Daemon Configuration --------------------------------

func daemonControls() []compliance.Control {
	return []compliance.Control{
		{
			ID: "2.1", Title: "Restrict network traffic between containers on the default bridge",
			Section: secDaemon, Level: compliance.Level1, Scored: true,
			Description: "With inter-container communication (icc) enabled, every container on the default bridge can reach every other, so one compromise sees the rest.",
			Remediation: `Set "icc": false in daemon.json and define explicit networks for containers that must talk.`,
			Fix:         daemonFix(`"icc": false`, "disable inter-container comms on default bridge; restart dockerd"),
			Frameworks:  []compliance.FrameworkRef{nist190("4.5.1"), nist53("SC-7"), stig("SRG-APP-000038")},
		},
		{
			ID: "2.2", Title: "Set the logging level to 'info'",
			Section: secDaemon, Level: compliance.Level1, Scored: true,
			Description: "Running the daemon at debug level leaks verbose operational detail and bloats logs; 'info' is the recommended production level.",
			Remediation: `Remove any "log-level" override or set "log-level": "info" in daemon.json.`,
			Fix:         daemonFix(`"log-level": "info"`, "set daemon log level to info"),
			Frameworks:  []compliance.FrameworkRef{nist190("4.5.2"), nist53("AU-2"), stig("SRG-APP-000089")},
		},
		{
			ID: "2.3", Title: "Allow Docker to make changes to iptables",
			Section: secDaemon, Level: compliance.Level1, Scored: true,
			Description: `Disabling iptables management ("iptables": false) leaves container network isolation to hand-maintained rules that drift and fail open.`,
			Remediation: `Do not set "iptables": false; let the daemon manage the firewall rules.`,
			Frameworks:  []compliance.FrameworkRef{nist190("4.5.1"), nist53("SC-7"), stig("SRG-APP-000038")},
		},
		{
			ID: "2.4", Title: "Do not use insecure registries",
			Section: secDaemon, Level: compliance.Level1, Scored: true,
			Description: "Insecure registries are contacted over plaintext without certificate validation, exposing images to tampering and MITM.",
			Remediation: `Remove all entries from "insecure-registries" and use TLS-secured registries only.`,
			Fix:         daemonFix(`"insecure-registries": []`, "clear insecure-registries list"),
			Frameworks:  []compliance.FrameworkRef{nist190("4.2.1"), nist53("SC-8"), pci("4.2.1")},
		},
		{
			ID: "2.5", Title: "Do not use the aufs storage driver",
			Section: secDaemon, Level: compliance.Level1, Scored: true,
			Description: "aufs is deprecated, unmaintained, and not in the mainline kernel; it is a stability and security liability.",
			Remediation: `Use overlay2 (or another supported driver): set "storage-driver": "overlay2".`,
			Frameworks:  []compliance.FrameworkRef{nist190("4.5"), nist53("CM-7"), stig("SRG-APP-000141")},
		},
		{
			ID: "2.6", Title: "Configure TLS authentication for the Docker daemon socket",
			Section: secDaemon, Level: compliance.Level1, Scored: true,
			Description: "A daemon listening on a TCP socket without mutual TLS lets anyone who can reach the port drive Docker as root.",
			Remediation: `When exposing a tcp:// host, set "tlsverify": true with "tlscacert"/"tlscert"/"tlskey".`,
			Frameworks:  []compliance.FrameworkRef{nist190("4.5.3"), nist53("IA-5"), stig("SRG-APP-000033"), pci("2.2.5")},
		},
		{
			ID: "2.8", Title: "Enable user namespace support",
			Section: secDaemon, Level: compliance.Level2, Scored: true,
			Description: "userns-remap maps container root to an unprivileged host UID, so a container escape does not land as host root.",
			Remediation: `Set "userns-remap": "default" (and provision subordinate UID/GID ranges).`,
			Fix:         daemonFix(`"userns-remap": "default"`, "enable user-namespace remapping"),
			Frameworks:  []compliance.FrameworkRef{nist190("4.5.1"), nist53("AC-6"), stig("SRG-APP-000243")},
		},
		{
			ID: "2.11", Title: "Ensure authorization for Docker client commands is enabled",
			Section: secDaemon, Level: compliance.Level2, Scored: true,
			Description: "Without an authorization plugin, any client that reaches the daemon has full, unaudited control.",
			Remediation: `Deploy an authz plugin and set "authorization-plugins": ["<plugin>"] in daemon.json.`,
			Frameworks:  []compliance.FrameworkRef{nist190("4.5.3"), nist53("AC-3"), stig("SRG-APP-000033")},
		},
		{
			ID: "2.12", Title: "Configure centralized and remote logging",
			Section: secDaemon, Level: compliance.Level2, Scored: true,
			Description: "Local json-file logs are lost when a host is compromised or recycled; ship logs off-box for tamper-evident retention.",
			Remediation: `Set a remote "log-driver" (e.g. "syslog", "fluentd") with a "log-opts" destination.`,
			Frameworks:  []compliance.FrameworkRef{nist190("4.5.2"), nist53("AU-4"), pci("10.5.4")},
		},
		{
			ID: "2.13", Title: "Ensure live restore is enabled",
			Section: secDaemon, Level: compliance.Level1, Scored: true,
			Description: "Without live-restore, a daemon restart kills running containers, tempting operators toward risky availability workarounds.",
			Remediation: `Set "live-restore": true in daemon.json.`,
			Fix:         daemonFix(`"live-restore": true`, "keep containers running across daemon restarts"),
			Frameworks:  []compliance.FrameworkRef{nist190("4.5"), nist53("CP-10"), stig("SRG-APP-000516")},
		},
		{
			ID: "2.14", Title: "Ensure the userland proxy is disabled",
			Section: secDaemon, Level: compliance.Level1, Scored: true,
			Description: "The userland proxy adds an unnecessary, occasionally-vulnerable data path; hairpin NAT via iptables is preferred.",
			Remediation: `Set "userland-proxy": false in daemon.json.`,
			Fix:         daemonFix(`"userland-proxy": false`, "disable the docker-proxy userland hop"),
			Frameworks:  []compliance.FrameworkRef{nist190("4.5.1"), nist53("CM-7"), stig("SRG-APP-000141")},
		},
		{
			ID: "2.15", Title: "Ensure a daemon-wide custom seccomp profile is not disabled",
			Section: secDaemon, Level: compliance.Level2, Scored: true,
			Description: `Setting "seccomp-profile": "unconfined" (or equivalent) strips syscall filtering from every container by default.`,
			Remediation: "Remove any daemon-level seccomp=unconfined; keep the built-in profile or supply a hardened one.",
			Frameworks:  []compliance.FrameworkRef{nist190("4.4.1"), nist53("SC-39"), stig("SRG-APP-000243")},
		},
		{
			ID: "2.16", Title: "Ensure experimental features are not enabled in production",
			Section: secDaemon, Level: compliance.Level1, Scored: true,
			Description: "Experimental features are unstable and may lack security review; they should not run in production.",
			Remediation: `Set "experimental": false (or omit it) in daemon.json.`,
			Fix:         daemonFix(`"experimental": false`, "disable experimental daemon features"),
			Frameworks:  []compliance.FrameworkRef{nist190("4.5"), nist53("CM-7"), stig("SRG-APP-000141")},
		},
		{
			ID: "2.17", Title: "Ensure containers are restricted from acquiring new privileges by default",
			Section: secDaemon, Level: compliance.Level2, Scored: true,
			Description: "no-new-privileges blocks setuid/setgid privilege escalation inside containers; setting it daemon-wide makes it the default.",
			Remediation: `Set "no-new-privileges": true in daemon.json.`,
			Fix:         daemonFix(`"no-new-privileges": true`, "block privilege escalation for all containers"),
			Frameworks:  []compliance.FrameworkRef{nist190("4.4.2"), nist53("AC-6"), stig("SRG-APP-000243")},
		},
	}
}
