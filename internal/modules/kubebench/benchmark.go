package kubebench

import "github.com/Ratnadeepdeyroy/docker-security/internal/compliance"

// --- framework-mapping shorthands ------------------------------------------

func nist53(id string) compliance.FrameworkRef { return compliance.Ref(compliance.FrameworkNIST53, id) }
func nsacisa(id string) compliance.FrameworkRef {
	return compliance.Ref(compliance.FrameworkNSACISA, id)
}
func stig(id string) compliance.FrameworkRef { return compliance.Ref(compliance.FrameworkSTIG, id) }

// Benchmark builds the CIS Kubernetes Benchmark catalogue for the resolved
// profile. The version and profile name come from profile resolution; the
// control set is the same catalogue, with per-section scoping applied by the
// checks (managed control-plane/etcd controls become INFO). Controls are pure
// data; pass/fail logic lives in the checks_*.go files keyed by control id.
func Benchmark(p Profile) compliance.Benchmark {
	return compliance.Benchmark{
		Code:    "k8s",
		Name:    "CIS Kubernetes Benchmark",
		Version: p.BenchmarkVersion,
		Profile: p.Name,
		Controls: concat(
			controlPlaneControls(),
			etcdControls(),
			nodeControls(),
			policyControls(),
		),
	}
}

func concat(groups ...[]compliance.Control) []compliance.Control {
	var out []compliance.Control
	for _, g := range groups {
		out = append(out, g...)
	}
	return out
}

// --- Section 1: Control Plane (API server) ---------------------------------

func controlPlaneControls() []compliance.Control {
	return []compliance.Control{
		cp("1.1.1", "Ensure the API server pod specification file permissions are 600 or more restrictive", compliance.Level1,
			"A world-readable/writable static-pod manifest lets a node-local user read secrets or alter how the API server starts.",
			"chmod 600 /etc/kubernetes/manifests/kube-apiserver.yaml",
			nist53("CM-6"), nsacisa("Pod-Security")),
		cp("1.1.2", "Ensure the API server pod specification file ownership is set to root:root", compliance.Level1,
			"Incorrect ownership of the manifest allows tampering with control-plane startup.",
			"chown root:root /etc/kubernetes/manifests/kube-apiserver.yaml",
			nist53("AC-6"), nsacisa("Pod-Security")),
		cp("1.2.1", "Ensure the --anonymous-auth argument is set to false", compliance.Level1,
			"Anonymous requests to the API server bypass authentication entirely.",
			"Set --anonymous-auth=false on the kube-apiserver.",
			nist53("IA-2"), nsacisa("Authentication")),
		cp("1.2.2", "Ensure the --token-auth-file parameter is not set", compliance.Level1,
			"Static token files are long-lived, unrotatable bearer credentials; prefer short-lived, pluggable auth.",
			"Remove --token-auth-file and use OIDC/webhook or client-cert auth.",
			nist53("IA-5"), nsacisa("Authentication")),
		cp("1.2.6", "Ensure the --authorization-mode argument is not set to AlwaysAllow", compliance.Level1,
			"AlwaysAllow disables authorization, granting every authenticated caller full access.",
			"Set --authorization-mode to Node,RBAC (never AlwaysAllow).",
			nist53("AC-3"), nsacisa("Authorization")),
		cp("1.2.7", "Ensure the --authorization-mode argument includes Node", compliance.Level1,
			"The Node authorizer restricts what kubelets can read/write to only their own node's objects.",
			"Include Node in --authorization-mode.",
			nist53("AC-3"), nsacisa("Authorization")),
		cp("1.2.8", "Ensure the --authorization-mode argument includes RBAC", compliance.Level1,
			"RBAC is the baseline for least-privilege authorization in Kubernetes.",
			"Include RBAC in --authorization-mode.",
			nist53("AC-3"), nsacisa("Authorization")),
		cp("1.2.11", "Ensure the admission control plugin AlwaysAdmit is not set", compliance.Level1,
			"AlwaysAdmit admits every request, defeating admission-time policy enforcement.",
			"Remove AlwaysAdmit from --enable-admission-plugins.",
			nist53("AC-3"), nsacisa("Pod-Security")),
		cp("1.2.16", "Ensure the admission control plugin NodeRestriction is set", compliance.Level1,
			"NodeRestriction limits a compromised kubelet to modifying only its own node and pods.",
			"Add NodeRestriction to --enable-admission-plugins.",
			nist53("AC-6"), nsacisa("Authorization")),
		cp("1.2.19", "Ensure the --profiling argument is set to false", compliance.Level1,
			"The profiling endpoint exposes sensitive runtime detail and widens the attack surface.",
			"Set --profiling=false on the kube-apiserver.",
			nist53("CM-7"), nsacisa("Audit-Logging")),
		cp("1.2.22", "Ensure the --audit-log-path argument is set", compliance.Level1,
			"Without an audit log there is no record of who did what — required by most frameworks.",
			"Set --audit-log-path (and retention/rotation flags) on the kube-apiserver.",
			nist53("AU-2"), nsacisa("Audit-Logging")),
		cp("1.2.31", "Ensure the --encryption-provider-config argument is set", compliance.Level1,
			"Without encryption-at-rest configuration, Secrets are stored in etcd in plaintext.",
			"Set --encryption-provider-config and enable a kms/aescbc provider.",
			nist53("SC-28"), nsacisa("Secrets")),
	}
}

func cp(id, title string, level compliance.Level, desc, rem string, refs ...compliance.FrameworkRef) compliance.Control {
	return ctl(id, secControlPlane, title, level, desc, rem, refs...)
}

// --- Section 2: etcd -------------------------------------------------------

func etcdControls() []compliance.Control {
	return []compliance.Control{
		et("2.1", "Ensure the --cert-file and --key-file arguments are set for etcd", compliance.Level1,
			"Without server TLS, etcd — which stores all cluster state including Secrets — accepts plaintext connections.",
			"Configure etcd with --cert-file and --key-file.",
			nist53("SC-8"), nsacisa("Encryption")),
		et("2.2", "Ensure the --client-cert-auth argument is set to true for etcd", compliance.Level1,
			"Without client certificate auth, any client that reaches etcd can read/modify all cluster state.",
			"Set --client-cert-auth=true on etcd.",
			nist53("IA-2"), nsacisa("Authentication")),
		et("2.3", "Ensure the --auto-tls argument is not set to true for etcd", compliance.Level1,
			"auto-tls makes etcd generate self-signed certs and accept them, undermining mutual authentication.",
			"Do not set --auto-tls=true; provision proper certificates.",
			nist53("IA-5"), nsacisa("Encryption")),
		et("2.4", "Ensure the --peer-cert-file and --peer-key-file arguments are set for etcd", compliance.Level1,
			"Peer TLS protects replication traffic between etcd members from interception.",
			"Configure etcd with --peer-cert-file and --peer-key-file.",
			nist53("SC-8"), nsacisa("Encryption")),
		et("2.5", "Ensure the --peer-client-cert-auth argument is set to true for etcd", compliance.Level1,
			"Without peer client-cert auth, a rogue peer can join and read/modify cluster state.",
			"Set --peer-client-cert-auth=true on etcd.",
			nist53("IA-2"), nsacisa("Authentication")),
		et("2.6", "Ensure the --peer-auto-tls argument is not set to true for etcd", compliance.Level1,
			"peer-auto-tls disables verification of peer identities.",
			"Do not set --peer-auto-tls=true.",
			nist53("IA-5"), nsacisa("Encryption")),
	}
}

func et(id, title string, level compliance.Level, desc, rem string, refs ...compliance.FrameworkRef) compliance.Control {
	return ctl(id, secEtcd, title, level, desc, rem, refs...)
}

// --- Section 4: Worker Node (kubelet) --------------------------------------

func nodeControls() []compliance.Control {
	return []compliance.Control{
		nd("4.1.9", "Ensure the kubelet config file permissions are 600 or more restrictive", compliance.Level1,
			"A readable kubelet config can leak sensitive parameters; a writable one lets a local user weaken the node.",
			"chmod 600 /var/lib/kubelet/config.yaml",
			nist53("CM-6"), nsacisa("Pod-Security")),
		nd("4.2.1", "Ensure the --anonymous-auth argument is set to false (kubelet)", compliance.Level1,
			"Anonymous access to the kubelet API allows unauthenticated command execution in pods.",
			"Set authentication.anonymous.enabled=false (or --anonymous-auth=false).",
			nist53("IA-2"), nsacisa("Authentication")),
		nd("4.2.2", "Ensure the --authorization-mode argument is not set to AlwaysAllow (kubelet)", compliance.Level1,
			"AlwaysAllow on the kubelet grants every caller full access to node/pod APIs.",
			"Set authorization.mode=Webhook (not AlwaysAllow).",
			nist53("AC-3"), nsacisa("Authorization")),
		nd("4.2.3", "Ensure the --client-ca-file argument is set (kubelet)", compliance.Level1,
			"Without a client CA the kubelet cannot verify API-server client certificates.",
			"Set authentication.x509.clientCAFile on the kubelet.",
			nist53("IA-5"), nsacisa("Authentication")),
		nd("4.2.4", "Ensure the --read-only-port argument is set to 0", compliance.Level1,
			"The read-only port (10255) exposes pod and node data without authentication.",
			"Set --read-only-port=0 (or readOnlyPort: 0).",
			nist53("AC-3"), nsacisa("Network-Separation")),
		nd("4.2.5", "Ensure the --streaming-connection-idle-timeout argument is not set to 0", compliance.Level2,
			"A zero idle timeout leaves exec/attach/port-forward streams open indefinitely, a resource-exhaustion vector.",
			"Set streamingConnectionIdleTimeout to a non-zero value (e.g. 5m).",
			nist53("SC-10"), nsacisa("Network-Separation")),
		nd("4.2.6", "Ensure the --make-iptables-util-chains argument is set to true", compliance.Level1,
			"Letting the kubelet manage iptables ensures the expected packet-filtering chains exist.",
			"Set makeIPTablesUtilChains: true (the default).",
			nist53("SC-7"), nsacisa("Network-Separation")),
		nd("4.2.9", "Ensure that the RotateKubeletServerCertificate argument is set to true", compliance.Level2,
			"Server certificate rotation limits the blast radius of a leaked kubelet serving cert.",
			"Enable RotateKubeletServerCertificate on the kubelet and controller-manager.",
			nist53("IA-5"), nsacisa("Encryption")),
	}
}

func nd(id, title string, level compliance.Level, desc, rem string, refs ...compliance.FrameworkRef) compliance.Control {
	return ctl(id, secNode, title, level, desc, rem, refs...)
}

// --- Section 5: Policies (RBAC & Pod Security) -----------------------------

func policyControls() []compliance.Control {
	return []compliance.Control{
		pol("5.1.1", "Ensure that the cluster-admin role is only used where required", compliance.Level1,
			"cluster-admin is unbounded superuser; broad or unnecessary bindings make one compromise total.",
			"Replace cluster-admin bindings with least-privilege roles; restrict to break-glass identities.",
			nist53("AC-6"), nsacisa("Authorization")),
		pol("5.1.3", "Minimize wildcard use in Roles and ClusterRoles", compliance.Level1,
			"Wildcard verbs/resources/apiGroups grant blanket access that makes privilege escalation trivial.",
			"Enumerate the specific apiGroups/resources/verbs each role needs; remove '*'.",
			nist53("AC-6"), nsacisa("Authorization")),
		pol("5.1.5", "Ensure that default service accounts are not actively used", compliance.Level1,
			"Workloads using the default SA (with token automount) get ambient credentials they rarely need.",
			"Set automountServiceAccountToken: false on default SAs and use per-workload SAs.",
			nist53("AC-6"), nsacisa("Authentication")),
		pol("5.2.2", "Minimize the admission of privileged containers (Pod Security)", compliance.Level1,
			"Namespaces without an enforced baseline/restricted Pod Security level admit privileged pods.",
			"Enable Pod Security Admission and label namespaces enforce=baseline or restricted.",
			nist53("AC-6"), nsacisa("Pod-Security")),
		pol("5.3.2", "Ensure that all namespaces have network policies defined", compliance.Level2,
			"Without a NetworkPolicy a namespace allows unrestricted pod-to-pod traffic (flat network).",
			"Define default-deny NetworkPolicies in every workload namespace.",
			nist53("SC-7"), nsacisa("Network-Separation")),
		pol("5.7.4", "Ensure that the default namespace is not used for workloads", compliance.Level2,
			"Concentrating workloads in the default namespace defeats namespace-scoped policy and RBAC boundaries.",
			"Place workloads in dedicated namespaces with their own policies and quotas.",
			nist53("AC-4"), nsacisa("Network-Separation")),
	}
}

func pol(id, title string, level compliance.Level, desc, rem string, refs ...compliance.FrameworkRef) compliance.Control {
	return ctl(id, secPolicy, title, level, desc, rem, refs...)
}

// ctl is the shared Control constructor (all scored) for this benchmark.
func ctl(id, section, title string, level compliance.Level, desc, rem string, refs ...compliance.FrameworkRef) compliance.Control {
	return compliance.Control{
		ID: id, Title: title, Section: section, Level: level, Scored: true,
		Description: desc, Remediation: rem, Frameworks: refs,
	}
}
