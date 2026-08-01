#!/usr/bin/env bash
# End-to-end local demo for docker-security. Builds a fixture image (no Docker
# required — it hand-crafts a docker-save tar), then drives every capability and
# prints the results. Fully offline and deterministic. No git is used.
set -euo pipefail
cd "$(dirname "$0")/.."

BIN=bin
DSECRAT="$BIN/dsecrat"
RUNTIME="$BIN/dsecrat-runtime"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

hr(){ printf '\n\033[1m== %s ==\033[0m\n' "$*"; }

hr "build"
mkdir -p "$BIN"
go build -o "$DSECRAT" ./cmd/dsecrat
go build -o "$RUNTIME" ./cmd/dsecrat-runtime
echo "built $DSECRAT + $RUNTIME"

# ---- craft a fixture image tar (docker save layout) -------------------------
ROOT="$WORK/rootfs"
mkdir -p "$ROOT/etc" \
         "$ROOT/lib/apk/db" \
         "$ROOT/app/node_modules/lodash" \
         "$ROOT/usr/lib/python3.11/site-packages/requests-2.30.0.dist-info" \
         "$ROOT/root/.ssh"
printf 'ID=alpine\nVERSION_ID=3.19.1\nPRETTY_NAME="Alpine Linux v3.19"\n' > "$ROOT/etc/os-release"
printf 'P:musl\nV:1.2.4-r2\nA:x86_64\nL:MIT\n\nP:busybox\nV:1.36.1-r5\nA:x86_64\nL:GPL-2.0-only\n\n' > "$ROOT/lib/apk/db/installed"
printf '{"name":"lodash","version":"4.17.20"}' > "$ROOT/app/node_modules/lodash/package.json"     # CVE-2021-23337
printf 'Name: requests\nVersion: 2.30.0\n\n' > "$ROOT/usr/lib/python3.11/site-packages/requests-2.30.0.dist-info/METADATA"  # CVE-2023-32681
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAAAAABAAAB\n-----END OPENSSH PRIVATE KEY-----\n' > "$ROOT/root/.ssh/id_rsa"  # secret
tar -C "$ROOT" -cf "$WORK/layer.tar" .
# Image config with a baked-in secret env + root user (imageaudit + secrets).
printf '{"config":{"User":"","Env":["PATH=/usr/bin","AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"],"ExposedPorts":{"22/tcp":{}}}}' > "$WORK/config.json"
printf '[{"Config":"config.json","RepoTags":["demo/app:latest"],"Layers":["layer.tar"]}]' > "$WORK/manifest.json"
IMG="$WORK/demo-image.tar"
tar -C "$WORK" -cf "$IMG" manifest.json config.json layer.tar
echo "fixture image: $IMG"

hr "dsecrat modules (all capabilities)"
"$DSECRAT" modules

hr "dsecrat scan <image> (all image-supporting modules, table)"
"$DSECRAT" scan "$IMG" || true

hr "dsecrat sbom --format cyclonedx (component count)"
"$DSECRAT" sbom --format cyclonedx "$IMG" | grep -c '"purl"' | sed 's/^/purls: /'

hr "dsecrat sbom --format spdx (validate JSON)"
"$DSECRAT" sbom --format spdx "$IMG" | python3 -c 'import sys,json;d=json.load(sys.stdin);print("spdx",d["spdxVersion"],len(d["packages"]),"packages")'

hr "dsecrat scan --modules vuln (CVE matches from the embedded DB)"
"$DSECRAT" scan --modules vuln "$IMG" || true

hr "dsecrat scan --modules secrets (embedded credentials)"
"$DSECRAT" scan --modules secrets "$IMG" || true

hr "dsecrat scan --fail-on high examples/Dockerfile.bad (CI gate → expect non-zero)"
if "$DSECRAT" scan --fail-on high examples/Dockerfile.bad >/dev/null; then echo "exit 0 (unexpected)"; else echo "exit $? — gate correctly blocked the build"; fi

hr "dsecrat-runtime replay (runtime threat detection)"
if [ -f internal/runtime/testdata/attack_scenario.json ]; then
  "$RUNTIME" replay internal/runtime/testdata/attack_scenario.json || true
else echo "skipped (no scenario fixture)"; fi

# ---- config/cluster modules: run against their committed fixtures if present -
run_if(){ # run_if <label> <fixture-glob> <cmd...>
  local label="$1"; shift; local glob="$1"; shift
  local f; f=$(ls $glob 2>/dev/null | head -1 || true)
  hr "$label"
  if [ -n "$f" ]; then "$@" "$f" || true; else echo "skipped (no fixture; needs a config/cluster target)"; fi
}
run_if "dsecrat harden gen-profile (seccomp)" 'internal/modules/harden/testdata/*.json' "$DSECRAT" harden gen-profile
run_if "dsecrat net (egress analysis)"        'internal/modules/netpolicy/testdata/*capture*.json' "$DSECRAT" net
run_if "dsecrat rbac (identity risk)"         'internal/modules/rbac/testdata/*.json internal/rbac/testdata/*.json' "$DSECRAT" rbac

hr "dsecrat compliance packs (versioned control packs)"
"$DSECRAT" compliance packs || true

hr "dsecrat compliance scan <image> (CIS/NIST/PCI/ISO/SSDF coverage + evidence)"
"$DSECRAT" compliance scan "$IMG" || true

hr "dsecrat compliance report --format oscal (auditor export, first lines)"
"$DSECRAT" compliance report --format oscal "$IMG" | head -12 || true

hr "dsecrat serve --store (HTTP API + web + MCP)"
"$DSECRAT" serve --store "$WORK/store" --addr 127.0.0.1:18234 >/dev/null 2>&1 &
SRV=$!; sleep 1
echo "GET /healthz    -> $(curl -s -o /dev/null -w '%{http_code}' 127.0.0.1:18234/healthz)"
echo "GET /v1/modules -> $(curl -s 127.0.0.1:18234/v1/modules | python3 -c 'import sys,json;print(len(json.load(sys.stdin)),"modules")')"
echo "GET /           -> $(curl -s -o /dev/null -w '%{http_code}' 127.0.0.1:18234/) (web dashboard)"
echo "POST /mcp       -> $(curl -s -o /dev/null -w '%{http_code}' -X POST 127.0.0.1:18234/mcp -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}') (agent interface)"
kill $SRV 2>/dev/null || true

hr "demo complete"
