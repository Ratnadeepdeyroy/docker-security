# Built-image CIS audit

**What:** audits a *built image's* config and layer history against CIS Docker Benchmark image controls — works
on any image, even one with no Dockerfile. **Where:** `internal/modules/imageaudit/`. **Domains:** 3, 10.
**Rule IDs:** `DS-RAT-IMG-*`.

## How it works

```mermaid
flowchart TD
    A["Image (tar / OCI layout)"] --> B["internal/oci: read config + layer history"]
    B --> C{"CIS-DI checks"}
    C --> K1["non-root USER — CIS-DI-0001"]
    C --> K2["HEALTHCHECK present — CIS-DI-0006"]
    C --> K3["no secrets in config/history — CIS-DI-0010"]
    C --> K4["base not :latest / digest pinned"]
    C --> K5["setuid/setgid binaries — CIS-DI-0008"]
    C --> K6["exposed / privileged ports"]
    C --> K7["required OCI labels (provenance)"]
    C --> K8["distroless / minimal → attack-surface score"]
    K1 & K2 & K3 & K4 & K5 & K6 & K7 & K8 --> F["[]Finding DS-RAT-IMG-*<br/>severity · control id · remediation"]
```

## Why it exists next to the Dockerfile linter
The Dockerfile linter audits the *recipe*; this audits the *artifact*. Most production images are pulled, not
built locally, and many ship without a Dockerfile — this covers them, and catches drift between recipe and
result.

## What it checks
Non-root user, HEALTHCHECK, secrets in config/history, base-image tag/digest hygiene, setuid/setgid binaries,
exposed/privileged ports, sensitive volumes, provenance labels, and a distroless/minimal attack-surface signal —
each mapped to a CIS-DI control id in the finding's references.

## Try it
```sh
docker save myapp:1.2.3 -o myapp.tar
dsecrat scan --modules imageaudit myapp.tar
```
*Status: built + integrated; CIS-DI results tested against committed image fixtures.*
