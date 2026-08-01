# F6 / F7 / F8 — Kubernetes: CIS Benchmark v1.10 · NSA/CISA v1.2 · K8s STIG

When Docker runs under Kubernetes, the orchestrator becomes the primary attack surface. Three frameworks
converge on the same technical controls: **CIS K8s v1.10** (prescriptive, per-setting), **NSA/CISA Hardening
Guidance v1.2** (risk-based), **K8s STIG** (DoD). Below = the shared technical baseline.

**Modules:** `kubebench` (CIS controls), `rbac` (identity), `admission`/`policy` (in progress), `netmon`
(planned), `imageaudit`/`vuln`/`verify` (workload images).

## Control plane & node (CIS K8s v1.10 — `kubebench`)
| Practice | Setting |
|---|---|
| API server hardening | `--anonymous-auth=false`, `--authorization-mode=Node,RBAC`, no `AlwaysAllow`, audit logging on |
| etcd | mutual TLS (`--peer-*`, `--cert/--key`), encryption at rest (`EncryptionConfiguration` + KMS) |
| kubelet | `--anonymous-auth=false`, `--authorization-mode=Webhook`, `--read-only-port=0`, rotate certs |
| Scheduler/controller | bind to localhost, `--profiling=false` |
| File perms | manifests + kubeconfigs 0600 root:root |

## Workload security (Pod Security + policy)
| Practice | Setting | Module |
|---|---|---|
| Pod Security Standards | enforce **restricted** PSS per namespace | `admission`/`policy` |
| Non-root + no-priv-esc | `runAsNonRoot: true`, `allowPrivilegeEscalation: false` | `admission` |
| Drop caps | `capabilities.drop: [ALL]` | `admission` |
| seccomp | `seccompProfile: RuntimeDefault` (or localhost profile) | `admission`, `harden` |
| Read-only rootfs | `readOnlyRootFilesystem: true` | `admission` |
| No host namespaces | `hostNetwork/PID/IPC: false` | `admission` |
| No privileged / hostPath | deny at admission | `admission` |
| Resource limits | requests/limits + LimitRange; PID limits | `admission` |

## Network (NSA/CISA emphasis — `netmon`, planned)
- **Default-deny** NetworkPolicy per namespace; explicit allowlists.
- Identity/label-based segmentation; DNS/FQDN egress control.
- Block cloud metadata (`169.254.169.254`) from pods.
- mTLS for service-to-service; encrypt node-to-node.

## Identity & RBAC (`rbac`)
- Least-privilege Roles; no wildcard verbs/resources; no cluster-admin sprawl.
- `automountServiceAccountToken: false` where the API isn't needed; bound short-lived tokens.
- Flag `escalate`/`bind`/`impersonate`, secret readers, `pods/exec`, proxy subresources, dangling bindings.

## Supply chain for workloads
- Admission verifies **signed images + attestations** (`verify`); scan images (`vuln`), SBOM (`sbom`), enforce
  trusted registries and digest pinning.

## Audit & logging
- API audit policy on, retained, shipped off-cluster (tamper-evident). Runtime detection (`runtime`, planned)
  ingests audit + syscall events → ATT&CK.

## How we deliver it
`kubebench` implements the CIS v1.10 control ids (with EKS/GKE/AKS profile variants that skip provider-owned
controls); `rbac` + `admission` cover identity and workload policy. All three K8s frameworks are **control
packs** that crosswalk onto the same checks — CIS gives the settings, NSA/CISA and STIG mostly re-map to them
(STIG adding FIPS + mandatory audit). Manual/cluster-inherited controls route to attestation.
