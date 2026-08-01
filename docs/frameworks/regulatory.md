# F9–F14 — Regulatory / governance frameworks (container-technical subset)

**NIST 800-53 Rev 5 · PCI DSS 4.0.1 · ISO/IEC 27001:2022 · SOC 2 · HIPAA Security Rule · FedRAMP (Rev 5).**

These are *outcome* frameworks — they say "protect data / control access / log events," not "set
`--cap-drop=ALL`." For containers they largely **consume the same technical evidence** the F1–F8/F15 checks
already produce, via the crosswalk. So the strategy is: **harden once (technical frameworks), map to each
regulation, and attest the organizational controls that no scanner can prove.**

**Modules:** the technical checks satisfy the *technical* controls; the `compliance` crosswalk + attestation
register handle mapping and the manual/organizational remainder.

## The shared technical control set (satisfies the container-relevant parts of all six)
| Theme | Container control | Modules | Maps to (examples) |
|---|---|---|---|
| Access control / least privilege | RBAC, non-root, no privileged, scoped tokens | `rbac`, `dockerbench`, `admission` | 800-53 **AC-2/3/6**, PCI **7**, ISO **A.5.15/A.8.2**, HIPAA **§164.312(a)** |
| Config hardening | CIS Docker/K8s baseline | `dockerbench`, `kubebench`, `imageaudit` | 800-53 **CM-6/CM-7**, PCI **2.2**, ISO **A.8.9**, FedRAMP CM |
| Vulnerability management | scan + prioritize + remediate + re-scan | `vuln` | 800-53 **RA-5/SI-2**, PCI **6.3/11.3**, ISO **A.8.8**, HIPAA risk-mgmt |
| Data protection / crypto | TLS on socket+registry, secrets mgmt, encryption at rest | `dockerbench`, `secrets`, `verify` | 800-53 **SC-8/SC-13/SC-28**, PCI **3/4**, ISO **A.8.24**, HIPAA **§164.312(e)** |
| Audit & accountability | daemon/API/audit logs shipped off-host, tamper-evident | `dockerbench`, `runtime` (planned) | 800-53 **AU-2/AU-6/AU-9**, PCI **10**, ISO **A.8.15**, HIPAA **§164.312(b)** |
| Network segmentation | default-deny egress, ICC off, segmentation | `netmon` (planned), `dockerbench` | 800-53 **SC-7**, PCI **1**, ISO **A.8.20/A.8.22** |
| Integrity / supply chain | sign+verify, SBOM, provenance | `sig`/`attest`/`verify`, `sbom` | 800-53 **SI-7/SR-**, PCI **6.3.2**, ISO **A.8.28**, SSDF |
| Malware / threat detection | image + runtime malware/behavior detection | `vuln`, `runtime` (planned) | 800-53 **SI-3/SI-4**, PCI **5**, ISO **A.8.7** |

## Per-framework specifics (what to remember)
- **NIST 800-53 Rev 5 (F9)** — the master control catalog; **FedRAMP baselines are subsets of it**. Our
  crosswalk hub: 800-190 and CIS both map to 800-53, and ISO 27001 has an official 800-53↔ISO mapping we reuse.
- **PCI DSS 4.0.1 (F10)** — all 4.0 requirements mandatory since Mar 2025. Container-heavy reqs: **1** (network
  segmentation of the CDE), **2** (hardening/no defaults), **6** (patch/secure dev), **10** (logging), **11**
  (scanning/pentest). Segmentation + scanning + logging evidence come straight from our checks.
- **ISO/IEC 27001:2022 (F11)** — Annex A (93 controls, 4 themes). Technical Annex A.8 controls map to our
  checks; A.5/A.6 (org/people) are **attestation** items.
- **SOC 2 (F12)** — Trust Services Criteria (Security/Availability/Confidentiality). Evidence-driven: our
  reproducible, timestamped evidence records + change/config + logging feed the CC-series criteria.
- **HIPAA Security Rule (F13)** — technical safeguards §164.312 (access, audit, integrity, transmission
  security) map to our controls; administrative/physical safeguards are **attestation**. (2025 NPRM proposes
  strengthening — track it.)
- **FedRAMP (F14)** — uses 800-53 Rev 5 baselines (Low/Mod/High); satisfy 800-53 technically + STIG where
  required, export **OSCAL**.

## How we deliver it (no coverage theater)
Each regulation is a **control pack** that is mostly `maps_to` targets pointing at the technical checks above,
plus explicit **`manual`/`inherited`** entries for the organizational, physical, and cloud-provider-owned
controls. Those route to the **attestation register** (owner, evidence link, expiry) and count toward coverage
**only when attested** — never auto-green. Output: per-framework coverage %, gaps, and an **OSCAL/PDF auditor
packet** with reproducible evidence.

**Bottom line:** harden to CIS/800-190/K8s, prove it with evidence once, crosswalk to all six regulations, and
attest the rest. One scan → many audits.
