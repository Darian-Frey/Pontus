> **Status:** Active
> **Provenance:** Shane Hartley (architect); Claude (document generation, primary auditor) — 2026-06-22
> **Last reviewed:** 2026-06-22
> **Why this status:** Five-phase plan agreed; nothing started. Phases are append-only — completed phases are marked with an ISO date, never deleted.

# Roadmap

Phases group features from [VISION.md](VISION.md). The ordering reflects D-006 (own the engine first) and D-007 (the asset store is the core, so it lands in Phase 1 alongside the engine — not bolted on later).

## Phase 1 — Foundation

**Goal:** A native Rust scan engine and the asset/observation store, driveable from the CLI — the shippable v0.1 core that everything else bolts onto.
**Status:** In progress
**Features delivered:** F-001, F-002, F-003, F-004, F-005, F-006, F-007
**Deliverables:**
- [x] `pontus-core`: host discovery — ARP + ICMP echo over IPv4 and IPv6 (TCP/UDP ping still to add; ARP yields MAC)
- [x] `pontus-core`: hybrid scan pipeline — stateless SYN sweep → stateful connect/banner deep pass; UDP scanning via connected sockets (large-range send-batching still to add)
- [x] `pontus-core`: `assets` + `observations` schema in SQLite, append-only observations (trigger-enforced)
- [x] `pontus-core`: host identity resolution (MAC → host key/cert → hostname → IP)
- [x] `pontus-core`: mandatory scope enforcement + audit log
- [x] `pontus-cli`: scan, list assets, diff (diff compares two scans by asset_id — opened/closed ports, new/vanished hosts, IP moves)
- [x] Smoke + integration test harness (38 tests: unit + public-API integration covering store/identity/scope/diff and real-socket connect scan; raw-socket paths validated manually on a live /24)

**Acceptance:** two CLI scans of the same subnet produce one asset per host and two observation sets; a forced IP change still resolves to the same asset; an out-of-scope target is refused before any packet is sent; results match Nmap host discovery and a SYN scan on a reference host within an explained delta.

---

## Phase 2 — GUI skeleton

**Goal:** A Qt6 desktop frontend whose home is the asset inventory; scanning becomes something you *do* to the inventory you *live in*.
**Status:** Complete (2026-06-25)
**Features delivered:** F-008, F-009, F-010, F-011
**Deliverables:**
- [x] `pontus-ffi`: stable C-ABI surface over `pontus-core` (assets/scans/history/diff/topology as JSON, plus a baseline write, + C header; scanning is deliberately a CLI shell-out, not FFI, per D-008)
- [x] `gui/`: Qt6 shell — asset table + detail pane as the home screen (filterable inventory + per-asset observation history over the FFI; scan launched from the CLI for now)
- [x] `gui/`: live force-directed topology graph from traceroute hop data (core ICMP traceroute → `edges` store → FFI `topology_json` → a Qt `QGraphicsView` force-directed graph, scanner pinned centre, pan/zoom)
- [x] `gui/`: scan profiles + GUI command builder (New-scan dialog with mandatory scope, TCP/UDP ports and live output, shelling out to the CLI per D-008; saveable profiles persisted via QSettings)
- [x] `gui/`: subnet service/port heatmap (host × open-service grid, columns ordered most-shared first so shared exposure forms vertical bands)

**Acceptance:** inventory persists across restarts; a scan launched from the GUI updates the table and the live topology graph; a saved profile round-trips (compose → save → reuse → run) entirely in the GUI.

---

## Phase 3 — Intelligence

**Goal:** Turn raw scan data into actionable signal — detection, change-tracking, and triage-grade vulnerability intelligence.
**Status:** In progress
**Features delivered:** F-012, F-013, F-014, F-015, F-016, F-017
**Deliverables:**
- [x] `Detector` trait with native default detector (`detect::NativeDetector` — clean-room banner grammar + well-known ports, C-001; wired into the CLI so observations carry structured service/version)
- [x] Optional Nmap-backed detector (`detect::NmapDetector` shells out to the user's own `nmap -sV` and parses its XML; never bundled, D-006/C-001; `pontus-cli --detector nmap`)
- [x] Native OS fingerprinting with an updatable corpus (`os` module: passive p0f-style family-level guess from the SYN-ACK's TCP-option layout + TTL + window + DF bit + volunteered banner tokens, scored against a clean-room corpus that layers a user JSON file over built-in defaults; distinguishes Linux/Windows/macOS by stack signature; `pontus-cli scan` records it, `--os-corpus` updates signatures without a rebuild; plus an optional `--os-detector nmap` backend that shells out to the user's own `nmap -O` for a version-range guess; D-011, C-001)
- [~] Scan diff + baseline designation + deviation view (all three landed early via the GUI: `diff_observations`, store-level baseline in a `meta` table, and the colour-coded drift view that defaults to the baseline)
- [x] CVE matching (NVD/OSV) with EPSS + CISA KEV enrichment and composite risk score (D-009 hybrid; `intel` module: CPE-applicability matching via the NVD CPE+CVE APIs, EPSS + KEV enrichment, and the C-002 exploitation-weighted risk engine; `pontus-cli scan --assess-vulns` stores vulns and `pontus-cli risk` ranks hosts fix-first; GUI risk view — `View ▸ Risk / vulnerabilities…` over a shared `store::risk_ranked` + FFI `risk_json`: hosts worst-first with a per-host CVE breakdown, band-coloured, KEV-badged)
- [ ] TLS/SSL inspection (chain, expiry, weak ciphers, SNI, CT cross-ref)
- [ ] HTTP tech fingerprinting

**Acceptance:** a port opening between scans surfaces as an explicit change against baseline; a host with a KEV-listed vulnerable service sorts above a host with only a high-CVSS/low-EPSS issue; switching detection backends improves coverage with no code change.

---

## Phase 4 — Monitoring & plugins

**Goal:** Make Pontus run unattended and become extensible.
**Status:** Not started
**Features delivered:** F-018, F-019, F-020, F-021, F-022
**Deliverables:**
- [ ] `pontus-daemon`: scheduled rescans persisting to the store
- [ ] Alert rules + delivery (desktop/email/webhook/Slack/Discord)
- [ ] `pontus-plugins`: stable `Finding` API with pyo3 / mlua / wasmtime runners (D-003)
- [ ] First-party plugins: SMB enum, SNMP walk, SSH host-key, HTTP header audit
- [ ] Credentialed scanning (user-supplied SSH/SNMP) for inventory depth

**Acceptance:** a scheduled rescan runs unattended and writes observations; a matching change fires exactly one alert on a configured channel; the same trivial plugin runs under all three runners and the WASM one cannot touch the filesystem.

---

## Phase 5 — Reporting & ecosystem

**Goal:** Fit Pontus into pipelines and broaden reach.
**Status:** Not started
**Features delivered:** F-023, F-024, F-025, F-026, F-027, F-028
**Deliverables:**
- [ ] Report builder: HTML/PDF, plus JSON-native output and SARIF 2.1
- [ ] REST API over the core
- [ ] Nmap XML import (migration bridge)
- [ ] Plugin registry with signature verification
- [ ] Enrichment: ASN/geo/WHOIS, cloud-provider tagging
- [ ] Windows release pipeline (core + GUI)

**Acceptance:** a scan exports to HTML, PDF, JSON and schema-valid SARIF 2.1; an existing Nmap XML imports with no loss in mapped fields; a signed registry plugin installs and an unsigned one is refused; core and GUI build and pass the smoke suite on Windows.

---

## Interface design tiers (Minimum / Good / Great)

A capability view of the GUI that cuts across the phases above, derived from a review of comparable tools (2026-06-24): Zenmap, runZero, Lansweeper, Angry IP Scanner, plus change-monitoring and vulnerability-prioritisation dashboards. Each item is tagged with the `F-NNN` that delivers it and the phase it lands in. The interface-specific features this review surfaced (F-029–F-035) were added to the feature register in VISION.md.

**Load-bearing principle — asset-centric, not scan-centric.** Zenmap organises its window around scans (Output / Ports-Hosts / Topology / Host-Details / Scans tabs); modern asset tools make the inventory the home and treat a scan as an event against it. That inversion is Pontus's thesis (D-007) and is the spine of the interface. The supporting principles, common to every source reviewed: breadth-first / progressive disclosure (overview → table → asset detail → observation → finding); sortable/filterable tables with saved views as the workhorse interaction; every screen actionable (a drift to investigate, a KEV to patch — never a raw dump); and scope surfaced as a visible safety feature, not a buried setting (F-007).

### Minimum — table stakes (makes it usable)

The credible v1; the read-side FFI (assets/history/scans/diff as JSON) already serves most of it.

- Asset inventory table as the home screen — sortable/filterable columns (identity, anchor tier, last-seen, open-port count, up/down), colour-coded status (F-008, Phase 2).
- Asset detail pane — identity resolution, open ports/services/banners, and the observation history (F-008, Phase 2).
- Scan launcher with the scope field front-and-centre and live output (F-010, Phase 2).
- Scan history list; pick two scans to compare (F-005/F-014, Phase 2).
- Global search/filter over the inventory (F-029, Phase 2).
- Inventory persists across restarts (F-008 acceptance; already true via SQLite).

### Good — what makes it better than Zenmap/Angry IP

The differentiating tier; this is where the asset model pays off.

- Drift / diff view — two scans (or baseline vs now) rendered as opened/closed ports, new/vanished hosts, IP-moves; colour-coded (F-014, Phase 3).
- Baselines — designate a reference scan and always diff against it (F-014, Phase 3).
- Saved views / smart filters — e.g. "port 22 open", "new since baseline", "SNMP-exposed" (F-030, Phase 2–3). Highest-leverage UX investment per the research.
- Overview dashboard — total assets, up/down, new-since-baseline, most-exposed services (F-031, Phase 2–3).
- Live topology graph — interactive force-directed from traceroute hops (F-009, Phase 2).
- Service/port heatmap — subnet-wide shared-exposure view (F-011, Phase 2).
- Tags, notes and ownership on assets, anchored on the durable asset (F-032, Phase 2–3).
- Export of any filtered view to CSV/JSON/report (F-023, Phase 5).

### Great — the platform vision

- Vulnerability triage queue ranked by exploitability, not severity — KEV badges, "fix-this-first" sort, composite per-host risk; the operational tiers are KEV → 24h, EPSS > 0.5 + CVSS > 7 → 7 days, else normal (F-015, C-002, Phase 3). The single feature that most elevates the tool.
- Time-travel — a timeline scrubber to view the estate's state at any past scan, and animate change over time (F-033, extends F-014, Phase 3+).
- Live scan visualisation — hosts/ports appearing on the graph as the scan runs (F-009, Phase 2+).
- Continuous-monitoring dashboard — scheduled rescans plus an alert feed/timeline (F-018/F-019, Phase 4).
- Per-asset risk-over-time (F-034, Phase 3+).
- Deep-inspection panels — TLS/cert (F-016), HTTP tech (F-017), plugin findings per asset (F-020/F-021); Phases 3–4.
- Command palette / keyboard-driven workflow (F-035, any phase).

**Deliberately deferred (anti-scope-creep, per the "don't over-engineer" pitfall):** drag-and-drop customisable widget dashboards and multi-user RBAC — enterprise-SaaS shape, not a focused desktop tool. Revisit only on real user demand.

<!--
When a phase completes, set its Status to "Complete (YYYY-MM-DD)" and tick its deliverables.
Do not delete completed phases — the historical sequence is itself documentation.
-->
