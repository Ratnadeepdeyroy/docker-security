# Deploying `dsecrat-runtime` (node runtime sensor)

`dsecrat-runtime` is a node-resident sensor that watches the processes, file
accesses, and network connections of every container on the host, runs them
through the deterministic `DS-RAT-RT-*` detection engine, and streams detections
to your chosen outputs. This directory holds ready-to-apply deployment assets.

- **Kubernetes:** `deploy/runtime/daemonset.yaml` — one pod per node.
- **Single Docker host:** `deploy/runtime/compose.yaml`.

## Two live sensors: eBPF (preferred) and `/proc` (fallback)

`run` auto-selects: if the kernel exposes BTF (`/sys/kernel/btf/vmlinux`) and the
eBPF program loads, it uses the **eBPF sensor** — every `execve` is captured
in-kernel with **no sampling gap** (short-lived processes are never missed).
Otherwise it falls back to the **`/proc`-polling source** (pure Go, no deps),
which samples state and can miss a process that starts and exits between polls.

**eBPF sensor requirements** (in addition to the access below): a BTF-capable
kernel (≥5.8), `CAP_BPF`+`CAP_PERFMON`+`CAP_SYS_ADMIN` (or privileged), a raised
memlock rlimit, and **tracefs mounted** at `/sys/kernel/tracing` (or debugfs at
`/sys/kernel/debug`) — the tracepoint attach needs it. Most nodes mount tracefs
by default; if attach fails with "neither debugfs nor tracefs are mounted", add a
`hostPath` mount for `/sys/kernel/tracing` (or mount it in an init step). If any
requirement is unmet the sensor logs the reason and falls back to `/proc`.

### The `/proc` fallback

Pure Go, no kernel modules, no eBPF dependency. Works on any Linux host.

- **Sees:** process exec (shell-in-container, binary drift, reverse shell,
  fileless `/dev/shm`/memfd execs, persistence writes, runtime-binary tamper),
  egress connections (C2, IMDS, IOC-feed matches), and file events surfaced
  through the runtime it can observe.
- **Samples state:** it polls `/proc` on an interval, so a process that starts
  **and** exits entirely between polls can be missed. Deep, exhaustive syscall
  and file-integrity coverage (every `openat`, `bpf()`, module load, with no
  sampling gap) is the job of the **eBPF sensor** (Track F), which is
  dependency-gated and not part of this manifest.
- **Off-Linux:** `run` exits cleanly with guidance to use offline `replay`.

## How `/proc` visibility works

Both manifests share the host PID namespace (`hostPID: true` / `pid: host`). That
makes the container's `/proc` the **host's** `/proc`, so the sensor reads every
process on the node directly — no `/host/proc` bind-mount needed. Container
attribution (image, name, privileged) is resolved best-effort through the
container runtime socket, mounted read-only.

### Required access
| Access | Why | Manifest |
|---|---|---|
| Host PID namespace | `/proc` = host process table | `hostPID`/`pid: host` |
| `SYS_PTRACE` capability | read `/proc/<pid>/exe` of other containers' processes | `capabilities.add` / `cap_add` |
| Runtime socket (ro) | container attribution (image/name/privileged) | `containerd.sock` / `docker.sock` |

No privileged mode. No eBPF capabilities. Read-only root filesystem.

## Outputs (fan-out)

Detections stream to any combination of sinks (all optional; stdout is always on):

- `--alert-file PATH` — append one JSON line per detection (durable audit trail a
  log shipper tails into a SIEM). Written `0600`.
- `--webhook URL` — POST each detection as JSON (Slack/Teams webhook, SIEM HTTP
  collector, incident endpoint).
- `--syslog` — send to the local syslog daemon (`LOG_AUTHPRIV`).

Multiple outputs run together and never short-circuit: a flaky webhook never
stops the file audit trail.

## Tuning: exceptions

Detections you have vetted as benign are suppressed with an exceptions file
(`--exceptions`). Matching is by rule id plus optional narrowing scope
(image, container, path-prefix, arg-substring) — prefix/substring only, no regex,
so every exception is auditable. Suppressed detections are counted (shown as
`suppressed=N` in the run summary) so tuning is measurable, not silent.

```json
{
  "exceptions": [
    { "rule_id": "DS-RAT-RT-001", "image_ref": "ci/runner:1", "note": "CI runner legitimately spawns shells" },
    { "rule_id": "DS-RAT-RT-004", "path_prefix": "/var/log/app/", "note": "app rotates its own logs" }
  ]
}
```

Supply it (and an optional threat-intel feed) via a ConfigMap:

```sh
kubectl -n dsecrat-system create configmap dsecrat-runtime-config \
  --from-file=exceptions.json \
  --from-file=intel.json      # optional
```

## Threat-intel feed (airgap-friendly)

`--intel-feed PATH` enables IOC matching (`DS-RAT-RT-014`) against a committed
JSON bundle of known-bad IPs/domains/hashes — no network fetch, so it works in
airgapped environments. Update it by replacing the file (or the ConfigMap key).

```json
{ "version": "2026.07",
  "ips":     { "203.0.113.5": "known-c2/cobaltstrike" },
  "domains": { "evil.example": "malware/dropper" },
  "hashes":  { "e3b0c4...": "miner/xmrig" } }
```

## Arming prevention (read before enabling)

By default the sensor is **detect-only**: it plans `kill`/`quarantine` actions and
records intent, but never acts. Prevention is **double-gated** — it arms ONLY with
BOTH:

```
--mode=enforce
--i-acknowledge
```

When armed, severe detections (at/above the kill severity) result in a real
`SIGKILL` of the offending process, and container escapes/kernel abuse pause and
network-isolate the whole container. **Blast radius:** a false positive can kill a
production workload. Start in detect mode, tune exceptions until the alert stream
is clean, and only then arm enforcement — ideally scoped to a canary node first.

## Verify a deployment

```sh
kubectl apply --dry-run=client -f deploy/runtime/daemonset.yaml   # schema check
kubectl -n dsecrat-system rollout status ds/dsecrat-runtime
kubectl -n dsecrat-system logs ds/dsecrat-runtime | head          # DS-RAT-RT-000 summary + any detections
```

To generate a test detection, exec a shell in any container on a node and watch
for `DS-RAT-RT-001` in the alert file/stream.

## Performance

Poll-based; the default cadence targets a small, bounded CPU/RSS footprint
(limits in the manifests: 200m CPU / 256Mi). Cost scales with process churn on
the node, not with total container count. If you need lower-overhead, gap-free
coverage, that is the eBPF sensor track.
