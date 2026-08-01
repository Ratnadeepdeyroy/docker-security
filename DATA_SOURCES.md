# Data Sources & Attribution

`dsecrat` embeds and (optionally, at runtime) fetches reference data. The **code**
is MIT-licensed, but some **data** originates from third parties and carries its
own copyright and attribution terms. This file documents the provenance of each
data set so redistributors can comply.

If you redistribute `dsecrat` with its bundled data, keep this file and honor the
per-source terms below.

---

## 1. Vulnerability advisories

### Embedded bootstrap snapshot
- **File:** `internal/vulndb/data/advisories.json`
- **Content:** a small curated set of well-known CVEs (identifiers, aliases, and
  short summaries) used so the tool is useful offline before a DB refresh.
- **Identifiers:** CVE IDs are assigned by the CVE Program (cve.org) and are
  free to use. GHSA aliases originate from the GitHub Advisory Database.
- **Summaries** derived from public advisory text may originate from the
  **GitHub Advisory Database / OSV**, licensed **CC-BY-4.0**
  (https://creativecommons.org/licenses/by/4.0/) — attribution required.

### Runtime refresh (`dsecrat vuln update`)
- **Source:** the public OSV export bucket
  `https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`
  (https://osv.dev).
- **License:** OSV records are **CC-BY-4.0**. Data fetched at runtime by the end
  user is not bundled by this project; the user is responsible for complying with
  OSV's license for any DB they build and redistribute.
- **Attribution:** "Vulnerability data from OSV (https://osv.dev),
  used under CC-BY-4.0."

### NVD CVE data (`dsecrat vuln update --nvd`)
- **Source:** the NVD CVE API 2.0 (https://nvd.nist.gov/developers/vulnerabilities),
  fetched at runtime by the end user.
- **License:** NVD data is a U.S. Government work — **public domain**. NVD asks
  that products not imply endorsement.
- **Attribution:** "This product uses data from the NVD API but is not endorsed
  or certified by the NVD."

### EPSS scores (`dsecrat vuln update --epss`)
- **Source:** the EPSS daily scoreset published by **FIRST.org**
  (https://www.first.org/epss), fetched at runtime by the end user.
- **License / attribution:** EPSS is free to use; credit FIRST.org —
  "EPSS data © FIRST.org (https://www.first.org/epss)."

### CISA KEV catalog (`dsecrat vuln update --kev`)
- **Source:** the CISA Known Exploited Vulnerabilities catalog
  (https://www.cisa.gov/known-exploited-vulnerabilities-catalog), fetched at
  runtime by the end user.
- **License:** U.S. Government work — **public domain**; crediting CISA is polite.

## 2. Compliance control packs

- **Files:** `internal/compliance/packs/*.json`

| Pack | Source | Copyright / License |
|------|--------|---------------------|
| `nist-800-190.json` | NIST SP 800-190 — https://csrc.nist.gov/publications/detail/sp/800-190/final | U.S. Government work — **public domain** |
| `nist-ssdf.json` | NIST SP 800-218 (SSDF) — https://csrc.nist.gov/pubs/sp/800/218/final | U.S. Government work — **public domain** |
| `cis-docker.json` | CIS Docker Benchmark — https://www.cisecurity.org/benchmark/docker | Benchmark content **© Center for Internet Security, Inc.** |

**NIST** publications are U.S. Government works and are not subject to copyright
in the United States — free to use and redistribute.

**CIS Benchmarks:** the full benchmark documents are copyrighted by the Center
for Internet Security. This project does **not** reproduce CIS's rationale,
audit, or remediation prose. It references **control identifiers** and uses its
**own** short titles, remediation wording, and cross-framework mappings for
interoperability — the standard approach for referencing a benchmark without
reproducing its copyrighted prose. If you redistribute the `cis-docker` pack,
retain this attribution:

    CIS control identifiers referenced under the terms of the Center for
    Internet Security. CIS Benchmarks® content is © Center for Internet
    Security, Inc. This project is not affiliated with or endorsed by CIS.

## 3. Malware signatures

- **File:** `internal/malware/data/signatures.json`
- **Content:** original detection signatures (filenames, string patterns, and
  hashes) authored for this project from publicly known malware behavior
  (e.g. common cryptominer binary names). No third-party signature database is
  bundled. **© 2026 Ratnadeep Dey Roy, MIT-licensed** with the rest of the code.

## 4. Framework / regulatory mappings

- Cross-references to NIST 800-53, PCI-DSS, ISO 27001, SOC 2, etc. in the packs
  are **factual control-ID mappings**, authored for this project. Standard *text*
  from PCI-SSC / ISO is **not** reproduced; only clause identifiers are cited.

---

## Summary for redistributors

- The **code** is MIT — see `LICENSE` and `NOTICE`.
- Keep this file and the `NOTICE` file with any redistribution.
- If you ship the embedded advisory data or a DB built via `dsecrat vuln update`,
  add: "Vulnerability data from OSV (https://osv.dev), CC-BY-4.0."
- If you ship the `cis-docker` pack, add the CIS attribution above.
- NIST-derived packs need no attribution (public domain) but crediting is polite.
