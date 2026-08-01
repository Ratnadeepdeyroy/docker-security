package rbac

// This file defines the normalized RBAC model we analyze over. It is a small,
// deliberately Kubernetes-shaped subset: enough of Role/Binding/ServiceAccount/
// Pod semantics to reason about permission and escalation, and nothing more. We
// keep the raw Kubernetes JSON shapes out of the analysis code by parsing them
// into these types once (see parse.go), so every analysis pass works against one
// stable model rather than the sprawling upstream schema.

// --- Core RBAC types -----------------------------------------------------

// PolicyRule is one grant inside a Role/ClusterRole: a set of verbs allowed on a
// set of resources (or non-resource URLs). Kubernetes evaluates rules additively
// — a subject may do X if *any* bound rule permits it — so risk is a union, not
// an intersection, and our analysis treats it that way.
type PolicyRule struct {
	APIGroups       []string
	Resources       []string
	ResourceNames   []string
	Verbs           []string
	NonResourceURLs []string
}

// Role is a namespaced or cluster-scoped set of permissions. We fold ClusterRole
// into the same type and distinguish with ClusterScoped, because their rule
// semantics are identical — only their reach differs.
type Role struct {
	Name          string
	Namespace     string // empty when ClusterScoped
	ClusterScoped bool
	Rules         []PolicyRule
	Labels        map[string]string
	// Aggregates is true when the role uses aggregationRule to absorb other
	// roles' rules; such roles are living permission sets and worth flagging.
	Aggregates bool
}

// Subject is a principal a binding grants a role to: a User, Group, or
// ServiceAccount. For ServiceAccounts, Namespace is meaningful.
type Subject struct {
	Kind      string // "User" | "Group" | "ServiceAccount"
	Name      string
	Namespace string
}

// key returns a stable identity string for graph indexing and deterministic
// output. ServiceAccounts are namespaced; Users/Groups are cluster-global.
func (s Subject) key() string {
	if s.Kind == "ServiceAccount" {
		return "ServiceAccount/" + s.Namespace + "/" + s.Name
	}
	return s.Kind + "/" + s.Name
}

// RoleRef points a binding at the Role or ClusterRole it grants.
type RoleRef struct {
	Kind string // "Role" | "ClusterRole"
	Name string
}

// Binding grants a RoleRef to a set of Subjects. RoleBinding is namespaced;
// ClusterRoleBinding (ClusterScoped) grants cluster-wide. A namespaced
// RoleBinding may still reference a ClusterRole — in which case the grant is
// scoped to the binding's namespace, which is a common source of confusion and
// mis-scoped access.
type Binding struct {
	Name          string
	Namespace     string // empty when ClusterScoped
	ClusterScoped bool
	Subjects      []Subject
	RoleRef       RoleRef
}

// ServiceAccount is a machine identity. AutomountToken mirrors the Kubernetes
// field: nil means "unset" (which defaults to mounting a token), so nil is not
// the same as false and we treat it as automounting.
type ServiceAccount struct {
	Name           string
	Namespace      string
	AutomountToken *bool
	Labels         map[string]string
	// LastUsed, when known (e.g. from an audit-usage fixture), lets the NHI
	// pass flag dormant automation identities. Zero means unknown.
	LastUsedUnix int64
	// Cloud, when non-nil, is the cloud IAM identity this ServiceAccount is
	// federated to via workload identity (IRSA / GKE / AKS). It is the bridge
	// where a compromised pod's K8s token becomes cloud credentials.
	Cloud *CloudIdentity
}

// CloudProvider names a cloud workload-identity mechanism.
type CloudProvider string

const (
	CloudAWS   CloudProvider = "aws"   // IRSA / EKS Pod Identity (eks.amazonaws.com/role-arn)
	CloudGCP   CloudProvider = "gcp"   // GKE Workload Identity (iam.gke.io/gcp-service-account)
	CloudAzure CloudProvider = "azure" // AKS Workload Identity (azure.workload.identity/client-id)
)

// CloudIdentity is the cloud IAM role a Kubernetes ServiceAccount is bound to
// through workload-identity federation. Analyzing this bridge is what turns
// "who can do what in the cluster" into "what cloud blast radius a pod inherits".
type CloudIdentity struct {
	Provider CloudProvider
	// Role is the provider-specific role reference: an IAM role ARN (AWS), a GCP
	// service-account email, or an Azure client id.
	Role string
	// Privilege, when supplied by the input, describes the bound role's power so
	// the analysis can flag over-privilege without querying the cloud. One of
	// "admin", "power", "write", "read", or "" (unknown).
	Privilege string
	// TrustAnyServiceAccount is true when the role's trust policy does not pin the
	// specific SA (subject condition) — a confused-deputy risk where any pod that
	// can present a token from the cluster's OIDC issuer can assume the role.
	TrustAnyServiceAccount bool
}

// automounts reports whether a token is mounted into pods using this SA. Unset
// (nil) defaults to true in Kubernetes.
func (sa ServiceAccount) automounts() bool { return sa.AutomountToken == nil || *sa.AutomountToken }

// Pod is a workload just detailed enough to tie it to an identity and its
// escalation-relevant security context. Escalation analysis starts from pods,
// because a compromised pod is the usual patient zero.
type Pod struct {
	Name               string
	Namespace          string
	ServiceAccountName string // empty means the namespace "default" SA
	AutomountToken     *bool
	Privileged         bool
	HostPID            bool
	HostNetwork        bool
	HostPathMounts     []string
	AddedCapabilities  []string
}

// effectiveSA returns the SA name a pod actually runs as ("default" when unset).
func (p Pod) effectiveSA() string {
	if p.ServiceAccountName == "" {
		return "default"
	}
	return p.ServiceAccountName
}

// --- Docker host model ---------------------------------------------------

// DockerHost captures the local-daemon identity surface. Membership of the
// docker group, or a mounted daemon socket, is effectively unaudited root — a
// classic non-Kubernetes privilege path we still want to catch.
type DockerHost struct {
	Name               string
	DockerGroupMembers []string
	Rootless           bool
	SocketMounts       []SocketMount
}

// SocketMount records a container that has the Docker daemon socket bind-mounted
// in — full control of the host's containers from inside one of them.
type SocketMount struct {
	Container string
	Path      string
}

// --- Cluster: the parsed universe ---------------------------------------

// Cluster is the whole parsed input: every object we will reason about. Maps are
// keyed for O(1) resolution during binding/role lookup; slices preserve nothing
// order-sensitive, so all analysis sorts its own output for determinism.
type Cluster struct {
	Roles           map[string]*Role // key: roleKey(clusterScoped, ns, name)
	Bindings        []*Binding
	ServiceAccounts map[string]*ServiceAccount // key: ns/name
	Pods            []*Pod
	DockerHosts     []*DockerHost
	// ObservedUsage maps a subject key to the permissions it was actually seen
	// using (from an audit fixture). Drives least-privilege generation and the
	// NHI dormant-identity check. Empty when no usage data was supplied.
	ObservedUsage map[string][]Permission
}

// newCluster returns an empty, ready-to-populate Cluster.
func newCluster() *Cluster {
	return &Cluster{
		Roles:           map[string]*Role{},
		ServiceAccounts: map[string]*ServiceAccount{},
		ObservedUsage:   map[string][]Permission{},
	}
}

// empty reports whether nothing RBAC-relevant was parsed. A generic filesystem
// scan that happens to contain unrelated JSON should produce no RBAC findings,
// so callers use this to stay silent rather than emit noise.
func (c *Cluster) empty() bool {
	return len(c.Roles) == 0 && len(c.Bindings) == 0 &&
		len(c.ServiceAccounts) == 0 && len(c.Pods) == 0 && len(c.DockerHosts) == 0
}

// roleKey builds the map key for a role. Cluster-scoped roles share one
// namespace-less space; namespaced roles are keyed by namespace too, because the
// same role name can exist independently in many namespaces.
func roleKey(clusterScoped bool, namespace, name string) string {
	if clusterScoped {
		return "ClusterRole/" + name
	}
	return "Role/" + namespace + "/" + name
}
