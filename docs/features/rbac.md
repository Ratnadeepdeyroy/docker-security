# Identity / RBAC risk

**What:** analyzes Kubernetes (and Docker) identity and RBAC for over-privilege and privilege-escalation paths —
the most common route from a compromised pod to cluster/cloud takeover. **Where:** `internal/rbac/`,
`internal/modules/rbac/`. **Domain:** 15. **Rule IDs:** `DS-RAT-RBAC-*`.

## How it works

```mermaid
flowchart TD
    A["K8s API objects: Roles · Bindings · ServiceAccounts<br/>(+ Docker: group / socket)"] --> B["Build RBAC graph<br/>subject → role → resource/verb"]
    B --> C{"Risk analysis"}
    C --> R1["escalate / bind / impersonate verbs"]
    C --> R2["wildcard verbs/resources"]
    C --> R3["secret get/list/watch (≈ cluster-admin)"]
    C --> R4["pods/exec · proxy subresources"]
    C --> R5["cluster-admin / system:masters holders"]
    C --> R6["dangling bindings · default SA · automount"]
    C --> R7["token-mint / CSR-sign paths"]
    R1 & R2 & R3 & R4 & R5 & R6 & R7 --> P["Escalation-path analysis<br/>pod → cluster-admin / node-root"]
    P --> F["[]Finding DS-RAT-RBAC-*<br/>+ least-privilege role suggestion"]
```

## What it does
- Builds a subject→permission graph and answers reverse queries ("who can do X on Y").
- Flags the classic escalation levers: `escalate`/`bind`/`impersonate`, wildcards, secret readers, `pods/exec`,
  proxy subresources, cluster-admin holders, dangling bindings, default-SA usage + automounted tokens,
  token-mint and CSR-signing paths.
- Traces multi-step **escalation paths** (pod → cluster-admin / node-root).
- Suggests least-privilege roles from observed/needed usage.

Analysis is pure over supplied API-object fixtures — no live cluster needed in tests.

## Try it
```sh
dsecrat scan --modules rbac /path/to/kube/rbac/objects
```
*Status: built + integrated; tested against a labeled cluster fixture.*
