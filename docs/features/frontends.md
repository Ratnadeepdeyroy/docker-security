# Frontends (CLI · HTTP · Web)

**What:** three interchangeable ways to drive the same engine. Nothing analysis-related lives here — frontends
only build a `Target`, call the engine, and render the `Report`. **Where:** `internal/cli/`, `internal/server/`,
`internal/web/`.

## One engine, three faces

```mermaid
flowchart TD
    subgraph In["Inbound adapters"]
        CLI["CLI (dsecrat)<br/>scan · sbom · serve · modules · version"]
        API["HTTP API<br/>/healthz · /v1/modules · /v1/scan"]
        WEB["Web dashboard<br/>embedded SPA at /"]
    end
    CLI --> ENG["engine.Run(ctx, target)"]
    API --> ENG
    WEB --> API
    ENG --> REP["Report"]
    REP --> FMT["Formatter: table · json · sarif"]
    FMT --> CLI
    FMT --> API
```

## CLI
```sh
dsecrat scan  [--format table|json|sarif] [--modules a,b] [--fail-on high] <target>
dsecrat sbom  [--format cyclonedx|spdx] [--out file] <image|path>
dsecrat serve [--addr :8080]
dsecrat modules      # list capabilities
dsecrat version
```
`--fail-on` turns any scan into a CI gate (non-zero exit at/above a severity).

## HTTP API
```mermaid
sequenceDiagram
    participant C as Client / CI / Agent
    participant H as HTTP server
    participant E as Engine
    C->>H: POST /v1/scan {type, content|location, modules, format}
    H->>E: Run(ctx, target, modules…)
    E-->>H: Report
    H-->>C: json (default) / table / sarif
```
`GET /healthz`, `GET /v1/modules`, `POST /v1/scan`. Same results as the CLI, by construction.

## Web dashboard
A self-contained single-page app embedded in the binary (`go:embed`) — no CDNs, works offline. Paste a
Dockerfile, pick modules, get findings ranked with severity badges. It is just a client of `/v1/scan`.

```sh
dsecrat serve --addr :8080   # open http://localhost:8080/
```
