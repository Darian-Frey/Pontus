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

### D-010 In-repo bug and improvement registers

**Decided:** 2026-06-26 · **Recorded:** 2026-06-26
**Status:** Accepted
**Authors:** Shane Hartley (architect); Claude (proposal)
**Related:** F-015 (the work that surfaced the first entries); the project documentation standard (project-scaffold)

**Context.** Bug history and code-quality observations have so far lived only in commit messages and the CHANGELOG `### Fixed`/`### Changed` sections — release-notes prose, not a defect/improvement register with status, reproduction and cross-references. Pontus deliberately keeps engineering knowledge in-repo registers (`F-NNN`, `C-NNN`, `D-NNN`) rather than an external tracker, and uses GitHub only for the PR/merge flow, not Issues. The documentation standard defines `BUGS.md` (realised failures, `BUG-NNN`) and `IMPROVEMENTS.md` ("works but could be better", `IMP-NNN`) as Tier 2 documents whose stated sweet spot is solo / AI-partner development that needs bug history to survive in-repo. The F-015 work produced concrete instances of both (two fixed bugs, two deferred limitations, three improvement candidates) that would otherwise evaporate into commit footnotes.

**Options.**
- **A. No register.** Rely on commit messages + CHANGELOG. Lightest; bug/improvement history is not durably tracked with status, reproduction or cross-references.
- **B. External issue tracker (GitHub Issues).** Standard tooling; but splits engineering knowledge out of the repo against the project's in-repo posture, and does not survive a forge migration.
- **C. In-repo `BUGS.md` + `IMPROVEMENTS.md`.** Append-only `BUG-NNN`/`IMP-NNN`, status-sectioned, with the "log when found/noticed, not silently acted on" discipline (Maintenance Rule 8). Consistent with the existing registers. *Chosen.*

**Decision.** Adopt `docs/BUGS.md` and `docs/IMPROVEMENTS.md` as Tier 2 registers with append-only `BUG-NNN`/`IMP-NNN` IDs, status sections, and the required-field discipline the standard specifies (reproduction for bugs, trade-offs for improvements). Both are maintained continuously: discoveries made while working on something else are logged before being acted on, so the author decides whether to fix/apply, defer or decline. The CLAUDE.md append-only-IDs convention is extended to include `BUG-NNN` and `IMP-NNN`.

**Consequences.** Bug and improvement history becomes durable, cross-referenced (to each other, to CHANGELOG, and to F-/D- entries) and forge-independent. Cost: a small standing discipline — logging discoveries rather than silently fixing them — which is especially load-bearing for the AI partner, whose default is to act inline.

**Reversal conditions.** If the project adopts an external issue tracker (GitHub Issues, Jira, Linear) as its primary workflow, retire the in-repo registers in its favour; likewise if the catalogues decay into after-the-fact records (entries logged only at commit time, adding nothing over the CHANGELOG), which would mean the log-when-found discipline has lapsed and the documents are no longer earning their keep. Either retirement is itself recorded as a decision.

### D-011 Passive, family-level, corpus-driven OS fingerprinting

**Decided:** 2026-06-26 · **Recorded:** 2026-06-26
**Status:** Accepted
**Authors:** Shane Hartley (architect); Claude (proposal)
**Related:** F-013, C-001, D-006

**Context.** F-013 needs OS identification, but the licensing trap (C-001) forbids vendoring or deriving from `nmap-os-db`, and a full *active* TCP/IP stack-fingerprinting engine (Nmap's 16-probe battery — crafted flag combinations, ISN sampling, IP-ID analysis) is large and operationally heavy. The feature's own acceptance is modest: bucket a handful of reference OSes *by family*, with a corpus updatable without a rebuild. The signals needed for family-level accuracy are cheaply and *passively* available from the SYN-ACK we already capture, which is how p0f fingerprints without sending probes: the initial TTL (a public IP-stack default), the advertised TCP window and don't-fragment bit, the OS tokens a host volunteers in service banners, and — most discriminating — the **order of the TCP options** the stack emits (MSS / SACK / Timestamp / NOP / Window-scale), which differs between Linux, Windows and macOS/BSD even when their TTLs coincide.

**Options.**
- **A. Active stack fingerprinting.** A clean-room reimplementation of Nmap-style probe sequences. Most precise (can reach version level); largest to build, slowest, and the closest to the C-001 line.
- **B. Shell out to `nmap -O`.** Mirror the D-006 detector pattern for OS detection. Accurate, no bundled data; but needs the user's Nmap and is a heavyweight dependency for a family-level guess.
- **C. Passive signals against a clean-room corpus.** Score the SYN-ACK's TCP-option layout, initial TTL, window and DF bit, plus volunteered banner tokens, against a built-in default corpus that a user JSON file layers over. Family-level; clean-room by construction; updatable without a rebuild. *Chosen as the default*, with **B offered as an opt-in backend** (`--os-detector nmap`) for users who want Nmap's version-range guess.

**Decision.** Implement OS fingerprinting as the `os` module fed by a `StackSignature` captured in the stateless sweep: the SYN-ACK's TCP-option *layout* (the order of MSS / SACK / Timestamp / NOP / Window-scale, the strongest passive discriminator), TTL, window and DF bit, plus banner tokens from the deep pass and the ICMP echo-reply TTL for portless hosts (IMP-006). These score against an `OsCorpus` whose built-in rules are first-principles (public IP-stack defaults and option orders; banner substrings matched against strings the host itself emits), never derived from `nmap-os-db` or any other fingerprint database. A `--os-corpus <path>` JSON file extends or overrides it at runtime. The guess (family, confidence, evidence) is recorded in the observation's existing `os_guess` field; confidence blends signal agreement with evidence strength so a lone TTL never reads as certainty (BUG-006). The work is structured behind an `OsDetector` trait (mirroring the service `Detector`, D-006): `NativeOsDetector` is the passive default, and `NmapOsDetector` (option B) shells out to the user's own `nmap -O` — parsing only the verdict Nmap prints, never reading `nmap-os-db` itself (C-001) — for a version-range guess. It needs raw-socket privilege, so `--os-detector nmap` is run via sudo.

**Consequences.** Family-level OS attribution — distinguishing Linux, Windows and macOS/BSD by their stack signature, not just TTL — lands cheaply and stays clear of the licensing trap, and the corpus is community-updatable. Cost: no version-level precision; option-layout rules need occasional tuning as stacks evolve (extensible via the corpus); and IPv6 loses the TTL/DF signals (the kernel strips the IP header on a raw v6 TCP socket), though the option layout and window survive (BUG-005). The shell-out (B) and active-probe (A) paths remain available as future precision backends.

**Reversal conditions.** If family-level accuracy proves insufficient and users need version-level OS identification, add either an active clean-room probe sequence (option A) or an optional `nmap -O` shell-out backend paralleling the D-006 detector (option B) — selected at runtime, never bundling `nmap-os-db`.

### D-012 Pure-Rust, clean-room TLS inspection (no OpenSSL)

**Decided:** 2026-06-27 · **Recorded:** 2026-06-27
**Status:** Accepted
**Authors:** Shane Hartley (architect); Claude (proposal)
**Related:** F-016, C-001, D-001

**Context.** TLS/SSL inspection (F-016) must observe what a *normal* TLS client never would: the *deprecated* protocols (SSLv3/TLS 1.0/1.1) and *weak* cipher suites a server still accepts, and the certificate even when it is expired or self-signed. The natural libraries pull in opposite directions. `rustls` is pure-Rust and cross-platform but deliberately refuses to speak legacy protocols or weak ciphers — so it cannot probe for them. System OpenSSL (`openssl` crate) can, but adds a C dependency (`libssl-dev`) that complicates the planned Phase 5 Windows release, and a modern OpenSSL has often compiled out the very protocols we want to test for. The project has repeatedly chosen to own its probe mechanisms clean-room (the native packet and UDP probes, C-001/D-006).

**Options.**
- **A. `rustls` only.** Pure-Rust cert inspection; cannot enumerate weak/legacy support (rustls won't offer it). Misses half the acceptance.
- **B. `openssl` crate.** Fullest active probing, but a system C dependency against an otherwise pure-Rust codebase, hostile to the Windows pipeline, and limited by what the local OpenSSL still supports.
- **C. Clean-room hand-rolled prober.** Construct `ClientHello`s and parse `ServerHello`/`Certificate` directly (the sslscan/testssl technique), delegating only X.509 parsing to `x509-parser`. Full control, no crypto/OpenSSL dependency, pure-Rust and cross-platform. *Chosen* (user decision, 2026-06-27).

**Decision.** Implement F-016 as the `tls` module: a hand-rolled prober that enumerates protocol support SSLv3–TLS 1.3, probes weak-cipher acceptance by offering a weak-only suite list, and captures the certificate from a TLS ≤1.2 `Certificate` message (in the clear), parsed by `x509-parser`. No OpenSSL, no crypto provider. A `pontus-cli tls <target>` command surfaces the report and honours scope enforcement (F-007) like any other active probe.

**Consequences.** Pontus can flag deprecated protocols, weak ciphers, and expired/self-signed/weak certificates with no C dependency, keeping the engine pure-Rust and Windows-friendly. Live-verified against badssl.com (expired, self-signed, 3DES-accepting endpoints). Cost: we maintain a little TLS wire parsing, and a **TLS 1.3-only** server encrypts its `Certificate`, so cert capture needs the server to also speak ≤1.2 (IMP follow-up); deep crypto validation (chain building, OCSP/CT) is out of scope for this cut.

**Reversal conditions.** If the wire parser becomes a maintenance burden, or we need full TLS 1.3 cert capture / chain validation / OCSP, adopt `rustls` (with a pure-Rust-friendly provider) for the *handshake and cert capture* while keeping the hand-rolled prober for the legacy-protocol/weak-cipher enumeration rustls cannot perform.
