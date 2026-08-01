# F1 — CIS Docker Benchmark (host · daemon · runtime)

The Docker-only prescriptive standard. Below: the practical technical controls that matter, the concrete
setting, and the `docker-security` check. Pull the current benchmark PDF from CIS — section numbers shift
between versions, so we check the *control*, not a frozen number.

**Modules:** `dockerbench` (host/daemon/runtime), `imageaudit` (images), `dockerfile` (build).

## 1. Host configuration
| Practice | Technical setting | Check |
|---|---|---|
| Isolate the container host | dedicated host/VM; minimal OS; up-to-date kernel | `dockerbench` host |
| Audit the Docker stack | `auditd` rules on `/usr/bin/dockerd`, `/etc/docker`, `/var/lib/docker`, `docker.service`, `docker.socket`, `/etc/default/docker`, `/etc/docker/daemon.json` | `dockerbench` host/auditd |
| Correct file ownership/perms | `/etc/docker` root:root; `daemon.json` 0644; `docker.sock` 0660 root:docker; certs 0444/0400 | `dockerbench` file-perms |

## 2. Docker daemon (`/etc/docker/daemon.json`)
Recommended hardened baseline:
```json
{
  "icc": false,
  "userns-remap": "default",
  "no-new-privileges": true,
  "live-restore": true,
  "userland-proxy": false,
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "default-ulimits": { "nofile": { "Hard": 1024, "Soft": 1024 } },
  "tlsverify": true,
  "tlscacert": "/etc/docker/ca.pem",
  "tlscert": "/etc/docker/server-cert.pem",
  "tlskey": "/etc/docker/server-key.pem",
  "seccomp-profile": "/etc/docker/seccomp-default.json"
}
```
| Practice | Why | Check |
|---|---|---|
| `icc: false` | disable inter-container comms on `docker0` (CIS 2.1) | `dockerbench` daemon |
| `userns-remap` | in-container root ≠ host root | `dockerbench` daemon |
| TLS + `tlsverify` on the socket | never expose `2375` plaintext; mutual TLS on `2376` | `dockerbench` daemon |
| No `--insecure-registry` | only TLS registries | `dockerbench` daemon |
| Enable an authz plugin | gate daemon API calls (not all-or-nothing) | `dockerbench` daemon |
| Live-restore, base seccomp not disabled, default ulimits | availability + syscall surface | `dockerbench` daemon |
| Never run dockerd with `--iptables=false` or default bridge in prod | keep firewall + segmentation | `dockerbench` daemon |

## 3. Container runtime (`docker run` flags)
| Practice | Flag | Check |
|---|---|---|
| Non-root user | `-u 1000` / image `USER`; verify not UID 0 | `dockerbench` runtime, `imageaudit` |
| Drop all caps, add minimal | `--cap-drop=ALL --cap-add=NET_BIND_SERVICE` (only if needed) | `dockerbench` runtime |
| No privilege escalation | `--security-opt=no-new-privileges` | `dockerbench` runtime |
| seccomp | default profile (not `--security-opt seccomp=unconfined`) | `dockerbench` runtime |
| AppArmor/SELinux | `--security-opt apparmor=docker-default` / SELinux labels | `dockerbench` runtime |
| Read-only rootfs | `--read-only` + `--tmpfs /tmp` | `dockerbench` runtime |
| No privileged | never `--privileged` | `dockerbench` runtime |
| No host namespaces | avoid `--pid=host --net=host --ipc=host --uts=host` | `dockerbench` runtime |
| No docker.sock mount | never `-v /var/run/docker.sock:...` | `dockerbench` runtime |
| Resource limits | `--memory --cpus --pids-limit=100 --restart=on-failure:5` | `dockerbench` runtime |
| Restrict devices | no `--device` to host block/char devices; keep default masked/ro paths | `dockerbench` runtime |
| Bind to loopback | `-p 127.0.0.1:8080:8080`, never `-p 0.0.0.0` unless intended | `dockerbench` runtime |
| Health | `HEALTHCHECK` present | `imageaudit` |

## 4. Swarm (if used)
Rotate join tokens; encrypt the overlay network (`--opt encrypted`); TLS + auto-rotating certs; manager
autolock enabled. → `dockerbench` swarm.

**Crosswalk:** each control maps to NIST 800-190 (§4 areas), 800-53 r5 (AC-6, CM-6, SC-7, SI-2, AU-2), PCI 4.0.1
(2.2, 1.x, 6.x), ISO 27001:2022 (A.8.9, A.8.20, A.8.22) — authored once in the control pack.
