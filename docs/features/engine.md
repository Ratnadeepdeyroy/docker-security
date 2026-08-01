# Engine & data model

**What:** the core that every frontend and module depends on. It defines the analysis `Target`, the unified
`Finding`/`Report` model, the `Module` plugin interface, and the `Engine` that runs modules and aggregates
results. **Where:** `internal/engine/`.

## The run pipeline

```mermaid
flowchart TD
    A["Frontend builds a Target<br/>(type · location · content)"] --> B["Engine.Run(ctx, target, names…)"]
    B --> C{"For each registered module"}
    C --> D{"module.Supports(target.Type)?"}
    D -- no --> C
    D -- yes --> E["module.Analyze(ctx, target)"]
    E -- findings --> F["Report.Add(findings)"]
    E -- error --> G["record in ModuleRuns<br/>(never fatal)"]
    F --> C
    C -- done --> H["sort by severity, then location"]
    H --> I["Report"]
    I --> J["Formatter: table · json · sarif"]
    I --> K["FailsAt(threshold) → exit code / gate"]
```

## How a scan flows through the parts

```mermaid
sequenceDiagram
    participant U as User / CI / Agent
    participant F as Frontend (CLI/HTTP)
    participant E as Engine
    participant M as Module(s)
    participant R as Report + Formatter
    U->>F: dsecrat scan <target>
    F->>E: Run(ctx, target)
    loop each supporting module
        E->>M: Analyze(ctx, target)
        M-->>E: []Finding (or error, recorded)
    end
    E->>E: sort + aggregate
    E->>R: Report
    R-->>F: table / json / sarif
    F-->>U: findings + exit code
```

## The data model (stable contract)

- **Target** — `{ Type; Location; Content; Metadata }`. Types: `dockerfile · image · filesystem · container · registry`.
- **Finding** — `{ RuleID; Module; Severity; Title; Description; Resource; Location; Remediation; References; Metadata }`.
- **Severity** — ordered: `Info < Low < Medium < High < Critical` (so sorting and gating are numeric).
- **Report** — findings + per-module run records; helpers `Counts()`, `Highest()`, `FailsAt(threshold)`.
- **Module** — `Name · Description · Domains · Supports(TargetType) · Analyze(ctx, *Target) ([]Finding, error)`.

## Why it's shaped this way
- **Isolation:** a module knows nothing about CLI/HTTP; a frontend knows nothing about scanning. Either side
  changes without touching the other.
- **Uniformity:** every capability produces the same `Finding`, so one formatter, one gate, one connector path
  serves all of them.
- **Resilience:** a failing module is recorded, never fatal — coverage degrades gracefully, never silently.
