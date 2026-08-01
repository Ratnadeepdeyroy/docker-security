# F2 — Image hardening (CIS-DI build controls)

Technical best practices for the image *artifact* and its Dockerfile — the cheapest place to eliminate risk.
Each maps to a CIS-DI control and the `dockerfile` (recipe) or `imageaudit` (built image) check.

**Modules:** `dockerfile`, `imageaudit`, `sbom`, `secrets`, `vuln`.

## Build the image right (Dockerfile)
| Practice | Concrete setting | CIS-DI | Check |
|---|---|---|---|
| Non-root user | `RUN adduser -D app` + `USER app` in final stage | DI-0001 | `dockerfile` DS-RAT-DF-002 |
| Pin base by digest | `FROM alpine:3.19@sha256:…` (never `:latest`) | DI-0005/0006 | `dockerfile` DS-RAT-DF-001/010 |
| Trusted registry only | `FROM` from an approved registry allowlist | — | `dockerfile` |
| No secrets in layers | use `RUN --mount=type=secret`, never `ENV`/`ARG` for creds | DI-0010 | `dockerfile` DS-RAT-DF-006, `secrets` |
| HEALTHCHECK | `HEALTHCHECK CMD …` | DI-0006 | `dockerfile` DS-RAT-DF-003, `imageaudit` |
| Minimize layers/pkgs | `--no-install-recommends`, clean apt lists in same `RUN` | DI-0007 | `dockerfile` DS-RAT-DF-005 |
| Prefer COPY over ADD | no remote-URL ADD, no tar auto-extract surprises | DI-0009 | `dockerfile` DS-RAT-DF-004 |
| Multi-stage builds | ship runtime only; drop compilers/SDKs | — | `dockerfile` / `imageaudit` |
| Verified downloads | no `curl \| sh`; download + checksum + run | — | `dockerfile` DS-RAT-DF-007 |

## Verify the built image (imageaudit)
| Practice | What it inspects | CIS-DI |
|---|---|---|
| Effective non-root user | image config `User` ≠ 0/empty | DI-0001 |
| No setuid/setgid binaries | scan layers for `+s` bits | DI-0008 |
| No secrets in config/history | env, labels, `docker history` | DI-0010 |
| Digest-pinned base, EOL base flagged | config + base metadata | DI-0005/0006 |
| Provenance labels present | `org.opencontainers.image.*` | — |
| Minimal / distroless | no shell / package manager → attack-surface score | — |

## Minimize + inventory + scan (the payoff)
- **Distroless / scratch runtime images** remove the shell and package manager — the single biggest
  attack-surface cut. `imageaudit` rewards it; aim for it.
- **SBOM every image** (`sbom` → SPDX + CycloneDX) so contents are known and vuln-scannable offline.
- **Scan for CVEs + secrets** (`vuln`, `secrets`) at build and at rest; **fail CI** on policy
  (`dsecrat scan --fail-on high`).
- **Sign + attest** (see [ssdf.md](ssdf.md)) so the hardened image is verifiable downstream.

## Golden recipe (hardened Dockerfile skeleton)
```dockerfile
FROM cgr.dev/chainguard/static@sha256:<digest>   # distroless, no shell
COPY --chown=65532:65532 app /app
USER 65532:65532
ENTRYPOINT ["/app"]
HEALTHCHECK CMD ["/app","-healthz"]
```
No shell, non-root, digest-pinned, no package manager, no secrets — passes DS-RAT-DF-* and most CIS-DI image
controls by construction.
