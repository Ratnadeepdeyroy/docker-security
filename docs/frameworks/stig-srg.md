# F3 / F5 — DISA STIG (Docker Enterprise 2.x) & Container Platform SRG

DoD-grade technical hardening. The **Container Platform SRG** (Dec 2020) defines *how a container platform goes
through the STIG process*; the **Docker Enterprise 2.x STIG (v2r1)** is the concrete, checkable Docker ruleset.
STIG is largely CIS Docker + NIST 800-53 r5, tightened and audit-mandatory for DoD/federal.

**Modules:** `dockerbench` (daemon/host), `imageaudit`/`dockerfile` (image), `compliance` (mapping + evidence),
`rbac` (access), `verify` (content trust).

## What STIG adds on top of the CIS baseline
| Area | STIG technical requirement | Check |
|---|---|---|
| **AuthN/Z** | daemon behind an **authorization plugin**; RBAC with least privilege; no anonymous access | `dockerbench` daemon, `rbac` |
| **FIPS crypto** | FIPS 140-2/3 validated modules for TLS and at-rest crypto | `dockerbench` daemon (TLS), doc/attest |
| **Audit** | full audit logging of daemon + API events, shipped off-host, tamper-evident, retained | `dockerbench` auditd |
| **TLS everywhere** | mutual TLS on the daemon socket and registry; no plaintext | `dockerbench` daemon |
| **Content trust** | only signed/verified images run (DCT/Notation/Cosign) | `verify`, `imageaudit` |
| **Least functionality** | disable unused features/ports/services; minimal base | `dockerbench`, `imageaudit` |
| **Session/timeout** | idle timeouts, session controls on management planes | `dockerbench` daemon |
| **Non-repudiation** | signed audit records; unique per-node identities/certs | `dockerbench`, `rbac` |
| **Vuln mgmt** | scan + remediate on a defined cadence; block known-vulnerable | `vuln`, policy gate |

## STIG-specific images
- **Docker Hardened Images (DHI)** ship **STIG variants** scanned against custom STIG-based profiles, with
  **signed STIG scan attestations** — prefer these as bases in DoD contexts; `verify` checks the attestation.
- No generic "container STIG" exists — general platforms use the **Container Platform SRG** process; Docker
  Enterprise has its own STIG.

## How we deliver it (compliance layer)
- A **STIG/SRG control pack** lists each STIG rule id,
  its assessment (`automated` → a `dockerbench`/`imageaudit`/`rbac` check, or `manual`/`inherited`), and the
  **crosswalk to NIST 800-53 r5** (STIGs are 800-53-derived, so this mapping is dense and mostly official).
- **Evidence** per rule (observed value, verdict, timestamp, host/image id) → **OSCAL** export for the eMASS /
  GRC workflow.
- Manual/organizational STIG rules (policy, personnel) route to the **attestation register** — counted only
  when attested, never auto-passed.

**Practical stance:** treat STIG as "CIS Docker + FIPS + mandatory audit + signed content + least
functionality + 800-53 mapping." Harden to CIS (see [cis-docker.md](cis-docker.md)), add FIPS crypto, enforce
signature verification, ship audit off-host, and let the control pack carry the STIG↔800-53 crosswalk +
evidence.
