package rbac

import (
	"fmt"
	"strings"

	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
)

// --- Cloud IAM trust-chain analysis (CAPABILITY_SPEC domain 15) -------------
//
// A Kubernetes ServiceAccount federated to a cloud IAM role via workload
// identity is the point where a compromised pod's in-cluster token becomes cloud
// credentials. The pod → SA → cloud-role chain is the most common real breakout,
// and it is invisible to pure in-cluster RBAC analysis. This file models that
// bridge and flags: over-privileged bound roles, confused-deputy trust policies
// that any SA can assume, and default-SA cloud bindings.

// Workload-identity annotation keys per provider.
const (
	annAWSRoleARN    = "eks.amazonaws.com/role-arn"
	annGCPServiceAcc = "iam.gke.io/gcp-service-account"
	annAzureClientID = "azure.workload.identity/client-id"
)

// cloudIdentity derives a CloudIdentity for a ServiceAccount from its
// workload-identity annotations and/or an explicit `cloud` descriptor. The
// explicit descriptor wins where both are present (it carries privilege/trust
// detail annotations cannot). Returns nil when the SA has no cloud binding.
func cloudIdentity(o *rawObject) *CloudIdentity {
	var ci *CloudIdentity

	ann := o.Metadata.Annotations
	switch {
	case ann[annAWSRoleARN] != "":
		ci = &CloudIdentity{Provider: CloudAWS, Role: ann[annAWSRoleARN]}
	case ann[annGCPServiceAcc] != "":
		ci = &CloudIdentity{Provider: CloudGCP, Role: ann[annGCPServiceAcc]}
	case ann[annAzureClientID] != "":
		ci = &CloudIdentity{Provider: CloudAzure, Role: ann[annAzureClientID]}
	}

	if o.Cloud != nil {
		if ci == nil {
			ci = &CloudIdentity{}
		}
		if p := CloudProvider(strings.ToLower(o.Cloud.Provider)); p != "" {
			ci.Provider = p
		}
		if o.Cloud.Role != "" {
			ci.Role = o.Cloud.Role
		}
		ci.Privilege = strings.ToLower(o.Cloud.Privilege)
		ci.TrustAnyServiceAccount = o.Cloud.TrustAnyServiceAccount
	}
	return ci
}

// privilegedRole reports whether a bound role's privilege level is broad enough
// that a pod inheriting it is a serious cloud blast-radius risk.
func privilegedRole(priv string) bool {
	switch strings.ToLower(priv) {
	case "admin", "power", "write":
		return true
	default:
		return false
	}
}

// checkCloudIAM analyzes every ServiceAccount's cloud binding. It is wired into
// checkAll and, like every other check, only appends Risks — never mutates state.
func checkCloudIAM(c *Cluster) []Risk {
	var rs []Risk
	for _, sa := range c.ServiceAccounts {
		ci := sa.Cloud
		if ci == nil {
			continue
		}
		subjectKey := "ServiceAccount/" + sa.Namespace + "/" + sa.Name
		provider := string(ci.Provider)

		// Over-privileged bound role: a compromised pod using this SA inherits
		// broad cloud permissions.
		if privilegedRole(ci.Privilege) {
			sev := engine.SeverityHigh
			if strings.EqualFold(ci.Privilege, "admin") {
				sev = engine.SeverityCritical
			}
			rs = append(rs, Risk{
				RuleID:      "DS-RAT-RBAC-030",
				Severity:    sev,
				Title:       fmt.Sprintf("ServiceAccount %q is bound to an over-privileged %s IAM role", sa.Name, provider),
				Description: fmt.Sprintf("SA %s/%s federates to cloud role %q with %q privilege. A pod that runs as this SA inherits those cloud permissions, so a container compromise becomes a cloud-account compromise.", sa.Namespace, sa.Name, ci.Role, ci.Privilege),
				Subject:     subjectKey,
				Resource:    ci.Role,
				Remediation: "Scope the cloud IAM role to the minimum permissions the workload needs; never bind admin/power roles to a pod identity.",
				References:  []string{"NIST SP 800-190 §4.3", "https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html"},
				Meta:        map[string]string{"provider": provider, "cloud_role": ci.Role, "privilege": ci.Privilege},
			})
		}

		// Confused-deputy trust: the role's trust policy does not pin this SA, so
		// any workload able to present a token from the cluster's OIDC issuer can
		// assume it.
		if ci.TrustAnyServiceAccount {
			rs = append(rs, Risk{
				RuleID:      "DS-RAT-RBAC-031",
				Severity:    engine.SeverityHigh,
				Title:       fmt.Sprintf("%s IAM role for %q trusts any ServiceAccount (confused deputy)", provider, sa.Name),
				Description: fmt.Sprintf("Cloud role %q trusts the cluster OIDC issuer without pinning the subject to %s/%s. Any pod in the cluster that can obtain a projected token can assume this role.", ci.Role, sa.Namespace, sa.Name),
				Subject:     subjectKey,
				Resource:    ci.Role,
				Remediation: "Add a subject/audience condition to the role trust policy that pins the exact ServiceAccount (system:serviceaccount:<ns>:<name>).",
				References:  []string{"https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html"},
				Meta:        map[string]string{"provider": provider, "cloud_role": ci.Role},
			})
		}

		// The default ServiceAccount should never carry a cloud identity — every
		// pod in the namespace that does not opt out runs as it.
		if sa.Name == "default" {
			rs = append(rs, Risk{
				RuleID:      "DS-RAT-RBAC-032",
				Severity:    engine.SeverityHigh,
				Title:       fmt.Sprintf("default ServiceAccount in %q is bound to a cloud IAM role", sa.Namespace),
				Description: fmt.Sprintf("The default SA in namespace %q federates to cloud role %q. Every pod that does not set its own serviceAccountName inherits these cloud permissions.", sa.Namespace, ci.Role),
				Subject:     subjectKey,
				Resource:    ci.Role,
				Remediation: "Bind cloud roles to purpose-specific ServiceAccounts, and set automountServiceAccountToken:false on the default SA.",
				References:  []string{"NIST SP 800-190 §4.3.1"},
				Meta:        map[string]string{"provider": provider, "cloud_role": ci.Role},
			})
		}
	}
	return rs
}
