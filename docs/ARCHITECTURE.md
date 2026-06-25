> **Status:** Active
> **Provenance:** Shane Hartley (architect); Claude (document generation, primary auditor) — 2026-06-22
> **Last reviewed:** 2026-06-22
> **Why this status:** Structure and decisions agreed at concept stage; module boundaries are provisional until Phase 1 implementation confirms them.

# Architecture

## Overview

Pontus is a three-tier system: a Qt6/C++ GUI frontend, a Rust core (`pontus-core`) exposed across a C-ABI shim, and a platform/integrations layer for raw sockets, intelligence feeds, notifications and export. The core is headless — the CLI and the GUI are both clients of it (D-001). The architectural centre of gravity is not the scan engine but the **asset inventory**: durable entities updated by scan events (D-007).

```
┌─────────────────────────────┐   ┌──────────────────────────┐
│  pontus-gui (Qt6 / C++20)   │   │  pontus-cli (Rust)       │
│  inventory · topology graph │   │  full client of core     │
└──────────────┬──────────────┘   └────────────┬─────────────┘
               │ C ABI (pontus-ffi)             │ direct
               ▼                                ▼
        ┌──────────────────────────────────────────┐
        │              pontus-core (Rust)            │
        │  ┌──────────────┐   ┌────────────────────┐ │
        │  │ packet engine│   │ asset/observation  │ │
        │  │ (Tokio,pnet) │──▶│ model (rusqlite)   │ │
        │  └──────────────┘   └────────────────────┘ │
        │  ┌──────────────┐   ┌────────────────────┐ │
        │  │ Detector     │   │ intelligence       │ │
        │  │ trait (D-006)│   │ (CVE/EPSS/KEV)     │ │
        │  └──────────────┘   └────────────────────┘ │
        └──────────────────────┬─────────────────────┘
                               ▼
        ┌──────────────────────────────────────────┐
        │  platform / integrations                   │
        │  raw sockets · NVD/OSV/EPSS/KEV feeds ·    │
        │  notifications · SARIF/PDF/JSON export ·   │
        │  plugin host (pyo3/mlua/wasmtime, D-003)   │
        └────────────────────────────────────────────┘
```

## Crate / module layout

- **`pontus-core`** — the engine. Owns the packet layer (host discovery, hybrid scan pipeline), the `Detector` trait, the asset/observation model, and the intelligence layer. No GUI or CLI concerns.
- **`pontus-ffi`** — the C-ABI shim. Stable, narrow surface so the Rust core and Qt GUI can release independently (D-001).
- **`pontus-cli`** — command-line client; the Phase 1 driver and the reference consumer of the core API.
- **`pontus-daemon`** — scheduled rescans and alert delivery (Phase 4).
- **`pontus-plugins`** — plugin host with three sandboxed runners (Phase 4, D-003).
- **`gui/`** — Qt6/C++20 desktop frontend (Phase 2).

## The scan pipeline (hybrid)

A scan is an event, not a mutation of state. The pipeline (C-005):

1. **Discovery** — find live hosts (ARP/ICMP/TCP/UDP).
2. **Stateless wide sweep** — masscan-style async SYN sweep across the port space; fast, shallow, no per-connection state.
3. **Stateful deep pass** — live ports from the sweep get careful stateful probing (banner, behaviour).
4. **Detection** — the `Detector` runs over deep-pass results (native default; optional Nmap-backed backend, D-006).
5. **Intelligence** — detected versions are matched to CVEs and enriched with EPSS/KEV (F-015).
6. **Observation write** — results are written as an append-only observation set against the resolved asset (D-007), never overwriting prior state.

## Data model

Two first-class tables (D-007):

- **`assets`** — durable host entities with a resolved identity (F-004). Identity resolution order is **MAC → stable host key / TLS cert fingerprint → hostname → IP** (C-003). The asset is the anchor for tags, notes, ownership and CVEs.
- **`observations`** — append-only, keyed by `(asset_id, scan_id, observed_at)`. Each records the host's state as seen by one scan: open ports, services, versions, OS guess, findings.

Drift, baselines and time-travel all fall out of querying observations over time against a stable `asset_id`. This is deliberately *not* full event-sourcing — a two-table relational shape is enough, and going further would be over-engineering (D-007 reversal note).

## Architectural invariants

These must hold; violating one is an architecture-level regression.

- **The core is headless.** No GUI- or CLI-specific logic in `pontus-core`. Both front-ends are clients.
- **Observations are append-only.** A scan never mutates or deletes a prior observation. Asset *identity* fields may be re-resolved; history is immutable.
- **Identity follows the fixed hierarchy.** MAC → host key/cert → hostname → IP. IP is the last resort, never the primary key.
- **Scope enforcement is unconditional.** No packet leaves for a target outside the declared scope (F-007). This cannot be disabled by configuration.
- **No bundled Nmap.** The Nmap-backed detector is a runtime shell-out to a user-provided binary; Nmap data files are never vendored (D-006, C-001).
- **IPv6 parity.** Any capability that works over IPv4 works over IPv6 unless physically impossible (D-004).
- **Untrusted plugins are sandboxed.** Community/WASM plugins run under wasmtime with no ambient filesystem or network authority (D-003).

---

## Decision register (D-NNN)

Append-only log of significant design decisions. Stable IDs, never reused. Reversed decisions get a new entry; the old one is marked `Superseded by D-NNN`. A decision without a reversal condition is a belief, not a decision.

Status vocabulary: Proposed | Accepted | Superseded by D-NNN | Deprecated.

---

### D-001 Rust core, Qt6 GUI, C-ABI bridge

**Decided:** 2026-05-23 · **Recorded:** 2026-06-22
**Status:** Accepted
**Authors:** Shane Hartley (architect); Claude (review)
**Related:** F-005, F-008

**Context.** Need a memory-safe, high-concurrency engine and a best-in-class desktop GUI, with independent release cadences for each.

**Options.**
- **A. Pure Rust + Rust-native GUI (egui/Slint/Tauri).** Single language; but topology-graph and large-table ergonomics were weaker at decision time.
- **B. C++ throughout.** Mature Qt, but loses Rust's safety and concurrency story in the engine.
- **C. Rust core + Qt6 GUI + C-ABI shim.** Best engine and best GUI; ABI decouples release cycles. *Chosen.*

**Decision.** Rust `pontus-core`, Qt6/C++20 GUI, connected by a narrow C-ABI shim (`pontus-ffi`).

**Consequences.** Two toolchains and an FFI boundary to maintain; in exchange, memory safety and async without a GIL in the engine, and a mature GUI. The CLI consumes the core directly, validating the API independently of the GUI.

**Reversal conditions.** If maintaining the C-ABI shim consumes a disproportionate share of engineering effort, or a Rust-native GUI toolkit (Slint, egui, Tauri+webview) demonstrably handles the live topology graph and large sortable asset tables at target scale, revisit the frontend choice.

---

### D-002 SQLite as the single source of truth

**Decided:** 2026-05-23 · **Recorded:** 2026-06-22
**Status:** Accepted
**Authors:** Shane Hartley (architect); Claude (review)
**Related:** F-003, F-014

**Context.** Asset inventory and history need durable, queryable, zero-admin storage usable from both front-ends.

**Options.**
- **A. Flat files (JSON/XML per scan).** Simple, but diffing and time-series queries become painful joins across files.
- **B. Embedded server (Postgres).** Powerful, but adds an admin burden inappropriate for a desktop tool.
- **C. SQLite (via `rusqlite`).** Embedded, transactional, no server, excellent query support. *Chosen.*

**Decision.** SQLite is the single store for assets, observations, config and history. No parallel file formats for state.

**Consequences.** One store to back up and migrate; rich queries for drift/baseline/time-travel for free. Very large estates may eventually stress single-file write throughput.

**Reversal conditions.** If observation volume at target scale (order 10⁷ rows) shows query or write latency SQLite can't meet even with proper indexing and WAL mode, migrate the observation store to an embedded columnar engine (e.g. DuckDB) while keeping SQLite for config/metadata.

---

### D-003 Tiered plugin isolation

**Decided:** 2026-05-23 · **Recorded:** 2026-06-22
**Status:** Accepted
**Authors:** Shane Hartley (architect); Claude (review)
**Related:** F-020, F-021, F-026

**Context.** Plugins range from trusted first-party scripts to untrusted community code; one isolation strategy can't serve both safely and ergonomically.

**Options.**
- **A. Single runtime for all.** Simple, but forces a trust/ergonomics compromise.
- **B. Tiered runners.** Match runtime to trust level. *Chosen.*

**Decision.** Three runners behind one stable `Finding` API: Python via **pyo3** (trusted, full-power), Lua via **mlua** (lightweight built-ins), WASM via **wasmtime** (untrusted community plugins, sandboxed — no ambient FS/network).

**Consequences.** Three runtimes to maintain; in exchange, community plugins are safe to run without trust, and first-party plugins keep full ergonomics.

**Reversal conditions.** If pyo3's GIL or packaging overhead proves prohibitive for the trusted path, or WASM component tooling matures enough to host all plugin classes uniformly at acceptable ergonomics, collapse the runner count.

---

### D-004 IPv6 native from Phase 1

**Decided:** 2026-05-23 · **Recorded:** 2026-06-22
**Status:** Accepted
**Authors:** Shane Hartley (architect); Claude (review)
**Related:** F-006

**Context.** Retrofitting IPv6 into a v4-shaped codebase is historically painful (Nmap's own history shows the cost of late dual-stack work).

**Options.**
- **A. IPv4 first, IPv6 later.** Faster to a demo; expensive to retrofit through the data model and scan paths.
- **B. Dual-stack from the first scan path.** *Chosen.*

**Decision.** IPv6 is a first-class address family from Phase 1, through discovery, scanning, the data model and the GUI.

**Consequences.** Slightly more design effort up front; avoids a costly retrofit and an awkward v4-only interim.

**Reversal conditions.** Treat as effectively permanent. The only trigger to reconsider would be a deliberate pivot to a dual-stack-free niche, which contradicts the asset-inventory goal.

---

### D-005 No bundled Nmap; reimplement all probe mechanisms

**Decided:** 2026-05-23 · **Recorded:** 2026-06-22
**Status:** Superseded by D-006
**Authors:** Shane Hartley (architect); Claude (review)
**Related:** C-001, D-006

**Context.** Original position: Pontus should reimplement *everything* Nmap does — discovery, scanning *and* detection — to avoid any Nmap dependency.

**Decision (as recorded).** Reimplement all probe and detection mechanisms natively; Nmap XML import is a convenience, not a runtime dependency.

**Consequences.** Clean licensing, but committed the project to reproducing 25 years of fingerprint curation from scratch — the most likely cause of the project stalling.

**Reversal conditions (as recorded).** "If native reimplementation of detection proves intractable, reconsider." — This trigger fired in design review: native detection parity is intractable on day one. Superseded by D-006.

---

### D-006 Own the packet engine; make deep detection pluggable

**Decided:** 2026-06-22 · **Recorded:** 2026-06-22
**Status:** Accepted
**Authors:** Shane Hartley (architect); Claude (review)
**Related:** C-001, C-005, D-005, F-001, F-002, F-012

**Context.** D-005 conflated two layers with very different cost profiles. The *packet engine* (discovery, scanning, the hybrid sweep) is tractable and is where the hybrid-speed advantage lives — it must be owned, because shelling out to Nmap forfeits control of timing and output granularity. The *fingerprint intelligence* is 25 years of curated data under a restrictive licence (C-001) and cannot be matched from scratch quickly, nor bundled without derivative-work entanglement.

**Options.**
- **A. Reimplement everything (D-005).** Clean but stalls on detection parity.
- **B. Shell out to Nmap for everything.** Fast to ship but forfeits the hybrid engine and makes Nmap load-bearing.
- **C. Own the packet engine; put detection behind a `Detector` trait — native default, optional Nmap-backed shell-out.** *Chosen.*

**Decision.** `pontus-core` owns host discovery and port scanning natively (Rust, Tokio, `pnet`). Deep detection (service/version/OS) sits behind a `Detector` trait: a modest native detector ships by default and grows over time; an optional detector shells out to the *user's own* installed `nmap` for best-in-class coverage. Nmap is never bundled, vendored or required.

**Consequences.** The hybrid-speed pipeline is achievable; licensing stays clean (runtime shell-out to a user binary is not a derivative work); Pontus is never "Zenmap with extra steps" yet offers immediate best-in-class detection to those who want it. Cost: a `Detector` abstraction and two detection backends to maintain.

**Reversal conditions.** If the native detector's coverage gap versus Nmap proves unacceptable to users *and* a clean-room, appropriately-licensed fingerprint corpus cannot be grown or sourced, reconsider whether deep detection should be native at all — but the shell-out backend, never bundled data, remains the licensing-safe fallback regardless.

---

### D-007 Asset inventory is the architectural core

**Decided:** 2026-06-22 · **Recorded:** 2026-06-22
**Status:** Accepted
**Authors:** Shane Hartley (architect); Claude (review)
**Related:** C-003, F-003, F-004, F-014

**Context.** Every differentiator — drift detection, baselines, time-travel, alerting — requires a host to be a durable entity whose state is observed over time. If the scan engine were the core and inventory a log of scan outputs, diffing would be an awkward retrospective join and the data model would fight every feature.

**Options.**
- **A. Scan-centric.** Scans are primary; inventory derived. Simpler initially; makes change-tracking a permanent struggle.
- **B. Asset-centric (durable entities + observation events).** *Chosen.*
- **C. Full event-sourcing.** Maximum auditability; over-engineered for the need.

**Decision.** Durable `Host`/`Service` entities are first-class; a scan run is an event producing append-only observations against the resolved asset. Two tables: `assets` and `observations` keyed by `(asset_id, scan_id, observed_at)`. Host identity resolves MAC → host key/cert → hostname → IP (C-003). The GUI home screen is the inventory; "scan" is an action that updates it.

**Consequences.** Drift/baseline/time-travel become straightforward queries; CVEs/tags/ownership hang off durable assets. Cost: an identity-resolution step on every scan and entity/observation indirection on reads.

**Reversal conditions.** If profiling shows the entity/observation indirection imposes unacceptable overhead for the dominant "single ad-hoc scan, no history" use case, add a lightweight stateless scan path that bypasses the asset store — without demoting the inventory as the default model.

---

### D-008 GUI shells out to the CLI for privileged scans

**Decided:** 2026-06-24 · **Recorded:** 2026-06-24
**Status:** Accepted
**Authors:** Shane Hartley (architect); Claude (review)
**Related:** D-001, D-006, F-007, F-010

**Context.** Raw-socket discovery and the SYN sweep need `CAP_NET_RAW`. The GUI needs to launch scans, but giving a large Qt/C++ binary raw-socket privilege widens the attack surface considerably, and the core scan path is async (Tokio) — calling it across the C-ABI would mean exposing and threading an async surface to keep the UI loop free.

**Options.**
- **A. In-process via `pontus-ffi`.** Add `pontus_scan()` and run the pipeline inside the GUI on a worker thread. Requires the GUI binary itself to hold `CAP_NET_RAW` (or run elevated); adds an async-over-C-ABI surface.
- **B. Shell out to the privileged `pontus-cli`.** The GUI spawns the `setcap`'d CLI as a subprocess writing the same store, streams its stdout for progress, and reloads the inventory on exit. *Chosen.*

**Decision.** The GUI runs scans by spawning `pontus-cli scan … --db <the open store>` as a child process. Raw-socket privilege stays confined to the small, audited CLI; the GUI holds no special privilege. The CLI's existing unprivileged TCP-connect fallback means scans still run (degraded) when the capability is absent.

**Consequences.** Privilege is isolated to one binary; the UI never blocks (separate process); the GUI reuses the exact, already-validated CLI scan path; and it works cross-platform (each OS elevates the CLI its own way) without elevating the GUI. Cost: the GUI must locate a compatible `pontus-cli`, and progress is parsed from CLI output rather than a structured API. Scope enforcement (F-007) is unaffected — it lives in the core the CLI drives, and the scan dialog surfaces the mandatory scope field.

**Reversal conditions.** If the GUI and CLI must ship as a single self-contained binary (e.g. a packaging or Windows-distribution constraint where a separate elevated helper is impractical), or progress/cancellation needs richer structured control than parsed output allows, revisit by exposing a scan surface over `pontus-ffi` — keeping privilege isolation via a separate elevated helper process rather than elevating the GUI itself.

---

### D-009 Hybrid vulnerability-data delivery

**Decided:** 2026-06-25 · **Recorded:** 2026-06-25
**Status:** Accepted
**Authors:** Shane Hartley (architect); Claude (review)
**Related:** F-015, C-002, C-001

**Context.** The intelligence layer (F-015) needs three data sources: CVE matching for a detected product/version, EPSS exploitation probabilities, and the CISA KEV catalogue. Unlike Nmap's fingerprint data (C-001), all three are freely/publicly licensed (NVD and KEV are US-government public domain; EPSS is free from FIRST; OSV is open), so caching or bundling them carries no licensing entanglement. The question is purely delivery: querying live APIs at scan time is always current but adds a hard network dependency, is subject to API rate limits, and is hard to test deterministically; bundling a full offline corpus (notably all of NVD) is self-contained but large to vendor/refresh and needs a heavier CPE-style matcher.

**Options.**
- **A. Online at scan time.** Query NVD/OSV + EPSS + KEV live per scan. Current, no vendored data; network-dependent, rate-limited, non-deterministic to test.
- **B. Fully offline (bundled snapshots).** Cache NVD + EPSS + KEV; match locally. Deterministic and offline; large NVD dataset and a heavier matcher.
- **C. Hybrid.** Cache the small, fast-moving feeds (KEV ~1.6k CVEs, EPSS) locally so enrichment and the risk scoring run offline and are unit-testable; query the NVD API on demand (cached) for CVE matching. *Chosen.*

**Decision.** The KEV catalogue and EPSS scores are fetched (`pontus-cli intel update`) and cached locally; the C-002 risk-scoring engine and enrichment operate entirely on local data and are testable without a network. CVE matching for a product/version queries the NVD API on demand, with results cached. Feeds are fetched with a minimal blocking HTTP client (`ureq`); nothing is vendored into the repository.

**Consequences.** The differentiating logic (exploitation-weighted scoring, KEV/EPSS enrichment) works offline and is deterministic to test; only CVE *matching* needs the network, and only for hosts with detected versions. Cost: a cache to manage and refresh, and NVD API rate limits to respect on the matching path.

**Reversal conditions.** If NVD API availability or rate limits prove too unreliable for the matching path, move that step to a bundled/cached NVD snapshot (toward option B) while keeping the same scoring engine; if cache staleness becomes a correctness problem for KEV/EPSS, shorten the refresh interval or fetch those inline.
