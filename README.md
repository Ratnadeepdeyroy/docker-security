# docker-security (`dsecrat`)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](go.mod)
[![Scanner deps](https://img.shields.io/badge/scanner%20deps-none-brightgreen)](go.mod)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20windows-blue)](#platform-support)

A from-scratch, unified **container-security tool** in Go — one engine, many
frontends (CLI, HTTP API, web dashboard, connectors). It covers the whole
container lifecycle: SBOM, vulnerability scanning, secret detection, static image
and Dockerfile analysis, license and malware gates, signing/attestation
verification, registry posture, CIS/NIST/PCI compliance, RBAC and cloud-IAM risk,
network-egress policy, container hardening, admission control, a Docker daemon
authorization plugin, continuous monitoring, and eBPF-backed runtime detection.

**Standard-library scanner** — the `dsecrat` scanner is built entirely on the Go
standard library and ships as a single static binary. The optional eBPF runtime
sensor (`dsecrat-runtime`, Linux) is the sole exception: it uses one dependency,
`github.com/cilium/ebpf`, isolated behind a `//go:build linux` tag so it never
enters the scanner binary.

> **Naming:** the project is **docker-security**; its CLI binary and Go package
> are **`dsecrat`** (`go install github.com/Ratnadeepdeyroy/docker-security/cmd/dsecrat@latest`).
> The runtime daemon is `dsecrat-runtime`. Rule IDs are prefixed `DS-RAT-…`.

> ☕ If this project is useful to you, you can
> [**buy me a coffee**](https://www.buymeacoffee.com/ratnadeepdeyroy).

## Highlights

- **18 capability modules** in one engine — run all with `dsecrat scan`, or list them with `dsecrat modules`.
- **Offline & deterministic** — no network required for a scan; the vulnerability DB and malware/compliance packs ship embedded and are refreshable.
- **CI-ready** — `--fail-on`, SARIF/JSON/OSCAL output, a policy-as-code gate, and connectors (webhook, Slack, SIEM, MCP).
- **Runtime & enforcement** — Kubernetes admission webhook, Docker daemon authorization plugin, continuous `watch` mode, and an eBPF sensor (Linux).

## Quickstart

```sh
make build        # → bin/dsecrat and bin/dsecrat-runtime
make test         # full test suite
make demo         # end-to-end: crafts a fixture image, drives every capability
make serve        # API + web dashboard + MCP on :8080 (with an inventory store)
make help         # list all targets
```

Or install straight from source with the Go toolchain:

```sh
go install github.com/Ratnadeepdeyroy/docker-security/cmd/dsecrat@latest
go install github.com/Ratnadeepdeyroy/docker-security/cmd/dsecrat-runtime@latest
```

No Docker is required to build or test.

## CLI

```sh
dsecrat modules                        # list capability modules
dsecrat scan <target>                  # scan a Dockerfile / path / image tar (all modules)
dsecrat scan --format json  <target>   # json | table | sarif
dsecrat scan --fail-on high <target>   # exit non-zero on a HIGH+ finding (CI gate)
dsecrat watch --interval 5m <target>   # continuous re-scan; emit only new findings
dsecrat sbom  --format spdx <target>   # SBOM: spdx | cyclonedx
dsecrat vuln  info                     # advisory DB status (age / count / staleness)
dsecrat vuln update --ecosystems Debian,Alpine,PyPI,npm --epss --kev   # refresh advisories + EPSS + CISA KEV
dsecrat vuln update --nvd --since 30d                                  # pull/refresh from the NVD CVE API (opt-in)
dsecrat vuln cron install                                             # self-updating: install a daily refresh job
dsecrat scan --vuln-db ~/.dsecrat/vulndb.json <target>    # scan against a refreshed/custom advisory DB
dsecrat compliance report --format oscal <target>   # auditor export: json|csv|oscal|md
dsecrat verify cosign --root fulcio.pem --cert leaf.pem \
     --payload payload.json --signature sig.bin \
     --certificate-identity ... --certificate-oidc-issuer ...   # keyless verify
dsecrat admission serve                # Kubernetes admission webhook
dsecrat authz serve                    # Docker daemon authorization plugin
dsecrat serve --addr :8080             # HTTP API + web dashboard
```

Example:

```sh
dsecrat scan examples/Dockerfile.bad
docker save alpine:3.19 -o alpine.tar
dsecrat sbom --format cyclonedx alpine.tar > alpine.cdx.json
```

## Capabilities

| Domain | Module(s) | What it does |
|---|---|---|
| SBOM | `sbom` | OS (apk/dpkg/rpm — sqlite, ndb, Berkeley DB) + language packages → SPDX / CycloneDX |
| Vulnerabilities | `vuln` | SBOM → CVE matching with per-ecosystem version compare, EPSS, KEV, VEX; embedded DB + `db update` |
| Static analysis | `dockerfile`, `imageaudit` | Dockerfile lint + built-image CIS audit (root, ports, secrets, setuid, provenance) |
| License policy | `license` | Allow/deny SPDX licenses & copyleft classes over the SBOM |
| Malware | `malware` | Static layer scan for miners, web/reverse shells, persistence, known-bad hashes (incl. deleted layers) |
| Secrets | `secrets` | Credentials in image layers (incl. deleted), filesystems, Dockerfiles; opt-in live verification |
| Supply chain | `verify` | Keyed **and** cosign/Fulcio keyless signature + attestation + Rekor-inclusion verification |
| Registry | `registry` | Trusted-registry allowlist, digest pinning, insecure-HTTP, typosquat detection |
| Compliance | `dockerbench`, `kubebench` + packs | CIS Docker/Kubernetes; crosswalk to NIST 800-190/800-53, PCI, SOC 2; OSCAL export |
| Policy / admission | `policy`, admission webhook, `authz` plugin | Policy-as-code gate, K8s admission, Docker daemon AuthZ |
| K8s manifests | `k8smanifest` | Offline posture lint of YAML/Helm/kustomize output (dependency-free YAML reader) |
| Identity / RBAC | `rbac` | Over-privilege, token exposure, escalation paths, and cloud-IAM (IRSA/GKE/AKS) trust-chain risk |
| Network | `netpolicy` | Egress analysis + least-privilege policy generation from observed flows |
| Hardening | `harden` | Container/pod/OCI posture verification + seccomp/AppArmor profile generation |
| Runtime | `runtime` (`dsecrat-runtime`) | ATT&CK-mapped detection & forensics; eBPF sensor on Linux, replay everywhere |

## Continuous monitoring

`dsecrat watch` turns a one-shot scan into monitoring: it re-scans on an interval,
diffs each run against the previous, and dispatches **only newly-appeared
findings** through the configured connectors — so a stable target stays quiet and
a regression (clean yesterday, vulnerable today) is surfaced immediately.

```sh
dsecrat watch --interval 5m --slack https://hooks.slack.com/... <target>
```

## Platform support

Pure Go, `CGO_ENABLED=0` → single static binaries. `make release` cross-builds
every target into `./dist`:

| OS | Arch | Notes |
|---|---|---|
| **Linux** | amd64, arm64 | full support incl. the live eBPF runtime sensor |
| **macOS** | amd64, arm64 | full (runtime sensor runs in replay mode) |
| **Windows** | amd64, arm64 | full (runtime sensor runs in replay mode) |

Every scanning capability is identical across platforms. The only OS-specific
piece is **live eBPF capture** in `dsecrat-runtime`, gated behind `//go:build linux`;
the binary builds and runs everywhere and live kernel capture activates only on
Linux.

## HTTP API & web dashboard

```sh
dsecrat serve --addr 127.0.0.1:8080     # then open http://localhost:8080/

curl localhost:8080/healthz
curl localhost:8080/v1/modules
curl -X POST localhost:8080/v1/scan -H 'Content-Type: application/json' -d '{
  "type": "dockerfile",
  "content": "FROM node:latest\nENV TOKEN=abc\n",
  "format": "json"
}'
```

The dashboard is embedded in the binary (no external assets, works offline).

## Documentation

- [Feature docs](docs/features/README.md) — one page per capability, with diagrams.
- [Framework playbooks](docs/frameworks/README.md) — technical hardening controls per framework.

## Contributing

Issues and pull requests are welcome. The project keeps two hard rules: **the
scanner stays standard-library-only** (the lone dependency, `cilium/ebpf`, is
confined to the Linux eBPF runtime sensor) and **every capability is tested**
(`go test ./...` must stay green on all platforms).

## License & attribution

[MIT](LICENSE) © Ratnadeep Dey Roy — https://github.com/Ratnadeepdeyroy/docker-security

`dsecrat` is free to use, fork, embed, and sell under the MIT License. The license
requires that the copyright notice (which names this project and its repository)
be retained in all copies and substantial portions.

**Please credit the project wherever you use it.** If you build on `dsecrat`, ship
it, or reference it, keep the [`NOTICE`](NOTICE) file and link back:

> Powered by **dsecrat** — https://github.com/Ratnadeepdeyroy/docker-security

- **Third-party code:** the scanner is pure Go standard library. The optional
  eBPF runtime sensor depends on [`github.com/cilium/ebpf`](https://github.com/cilium/ebpf)
  (Apache-2.0) — the one third-party license to track, and only when building
  `dsecrat-runtime` for Linux.
- **Bundled & fetched data** (advisories, EPSS, KEV, compliance packs, malware
  signatures) has its own provenance and attribution terms — see
  [`DATA_SOURCES.md`](DATA_SOURCES.md).

## Support

If `dsecrat` saves you time, please consider starring the repo ⭐ and
[buying me a coffee](https://www.buymeacoffee.com/ratnadeepdeyroy).

### Star history

A ⭐ helps others discover `dsecrat` — see the
[**star history**](https://star-history.com/#Ratnadeepdeyroy/docker-security&Date).

<!-- Once the repo has a few stars, swap the link above for the live chart:
[![Star History Chart](https://api.star-history.com/svg?repos=Ratnadeepdeyroy/docker-security&type=Date)](https://star-history.com/#Ratnadeepdeyroy/docker-security&Date)
-->

