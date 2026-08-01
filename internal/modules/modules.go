// Package modules wires the available capability modules into a registry.
// Frontends call Default() rather than importing individual modules, so adding
// a capability is a one-line change here.
package modules

import (
	"github.com/Ratnadeepdeyroy/docker-security/internal/engine"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/attacksim"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/dockerbench"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/dockerfile"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/harden"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/imageaudit"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/k8smanifest"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/kubebench"
	licensemod "github.com/Ratnadeepdeyroy/docker-security/internal/modules/license"
	malwaremod "github.com/Ratnadeepdeyroy/docker-security/internal/modules/malware"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/netpolicy"
	policymod "github.com/Ratnadeepdeyroy/docker-security/internal/modules/policy"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/rbac"
	registrymod "github.com/Ratnadeepdeyroy/docker-security/internal/modules/registry"
	runtimemod "github.com/Ratnadeepdeyroy/docker-security/internal/modules/runtime"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/sbom"
	secretsmod "github.com/Ratnadeepdeyroy/docker-security/internal/modules/secrets"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/verify"
	"github.com/Ratnadeepdeyroy/docker-security/internal/modules/vuln"
)

// Default returns a registry populated with every built-in module.
func Default() *engine.Registry {
	r := engine.NewRegistry()
	r.Register(dockerfile.New())
	r.Register(sbom.New())
	imageaudit.Register(r)  // Phase 1e — CIS/best-practice image audit (domains 3,10)
	secretsmod.Register(r)  // Phase 1d — secret detection (domain 7)
	vuln.Register(r)        // Phase 1c — vulnerability matching (domain 2)
	dockerbench.Register(r) // Phase 3 — CIS Docker Benchmark (domain 10)
	kubebench.Register(r)   // Phase 3 — CIS Kubernetes Benchmark (domain 10)
	verify.Register(r)      // Phase 2 — signature/attestation verification (domains 9,13)
	rbac.Register(r)        // Phase 8 — RBAC/identity risk (domains 7,15)
	attacksim.Register(r)   // Phase 8 — attack simulation harness (domain 14)
	netpolicy.Register(r)   // Phase 6 — network egress policy & anomaly detection (domain 6)
	harden.Register(r)      // Phase 7 — seccomp/AppArmor profile-gen & hardening checks (domain 12)
	policymod.Register(r)   // Phase 4 — policy-as-code CI gate (domain 8)
	licensemod.Register(r)  // license-policy gate over the SBOM (domains 1,8)
	malwaremod.Register(r)  // static malware/cryptominer layer scan (domains 3,11)
	k8smanifest.Register(r) // offline K8s manifest posture linter (domains 8,10)
	registrymod.Register(r) // Phase 2 — registry security & artifact-mgmt posture (domain 13)
	runtimemod.Register(r)  // Phase 5 — runtime threat detection (domains 4,5,11)
	return r
}
