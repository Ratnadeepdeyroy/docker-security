# Sandboxing & hardening

**What:** verifies a container/pod/OCI spec's runtime confinement posture and **generates least-privilege
profiles** (seccomp, AppArmor/SELinux) — plus an agent-appliable hardening bundle. Orchestrates existing
runtimes (gVisor/Kata) via RuntimeClass; it is not a new sandbox kernel. **Where:** `internal/harden/`,
`internal/modules/harden/`. **Domain:** 12. **Rule IDs:** `DS-RAT-BOX-*`.

## How it works

```mermaid
flowchart TD
    SPEC["container / pod / OCI spec"] --> VER{"hardening verification"}
    VER --> V1["non-root · runAsNonRoot"]
    VER --> V2["cap-drop ALL · no escape-prone caps"]
    VER --> V3["no-new-privileges"]
    VER --> V4["read-only rootfs"]
    VER --> V5["no host namespaces · no docker.sock"]
    VER --> V6["seccomp ≠ unconfined · AppArmor/SELinux"]
    VER --> V7["cgroup mem/pids limits"]
    VER --> V8["no privileged · sensitive mounts"]
    V1 & V2 & V3 & V4 & V5 & V6 & V7 & V8 --> F["findings DS-RAT-BOX-* + RuntimeClass guidance"]
    OBS["observed syscalls (from runtime)"] --> GEN["generate seccomp / AppArmor profile"]
    GEN --> B["bundle.go: agent-appliable securityContext + profile (dry-run diff)"]
```

## What it does
- **Verify posture** (`harden.go`, rules `DS-RAT-BOX-001…020`): checks the full least-privilege control set —
  non-root, cap-drop-ALL, no-new-privileges, read-only rootfs, no host ns, no `docker.sock`, seccomp/AppArmor
  applied, cgroup limits, no privileged, sensitive mounts, setuid neutralization.
- **Generate profiles**: least-privilege seccomp from observed syscalls; AppArmor/SELinux drafts.
- **Agent-appliable bundle** (`bundle.go`): a structured securityContext + profile set an AI platform agent can
  apply, with a dry-run diff of what it newly blocks (`DS-RAT-BOX-900`).
- **RuntimeClass guidance**: recommend runc vs gVisor vs Kata by workload trust level.

## Try it
```sh
dsecrat scan --modules harden <spec>          # verify posture
dsecrat harden ...                            # generate profile / bundle (see command.go)
```
**Status:** built + integrated; verification + profile generation tested (`harden_test.go`). Profile generation
consumes runtime-observed syscalls (domain 12 ↔ 4/5/11).
