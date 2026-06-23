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
- [ ] `pontus-core`: hybrid scan pipeline — stateless wide sweep → stateful deep pass
- [x] `pontus-core`: `assets` + `observations` schema in SQLite, append-only observations (trigger-enforced)
- [x] `pontus-core`: host identity resolution (MAC → host key/cert → hostname → IP)
- [x] `pontus-core`: mandatory scope enforcement + audit log
- [~] `pontus-cli`: scan, list assets, diff (scan + assets done; diff pending)
- [~] Smoke + integration test harness against a known reference subnet (unit tests in place; live /24 validated manually)

**Acceptance:** two CLI scans of the same subnet produce one asset per host and two observation sets; a forced IP change still resolves to the same asset; an out-of-scope target is refused before any packet is sent; results match Nmap host discovery and a SYN scan on a reference host within an explained delta.

---

## Phase 2 — GUI skeleton

**Goal:** A Qt6 desktop frontend whose home is the asset inventory; scanning becomes something you *do* to the inventory you *live in*.
**Status:** Not started
**Features delivered:** F-008, F-009, F-010, F-011
**Deliverables:**
- [ ] `pontus-ffi`: stable C-ABI surface over `pontus-core`
- [ ] `gui/`: Qt6 shell — asset table + detail pane as the home screen
- [ ] `gui/`: live force-directed topology graph from traceroute hop data
- [ ] `gui/`: scan profiles + GUI command builder (no CLI knowledge required)
- [ ] `gui/`: subnet service/port heatmap

**Acceptance:** inventory persists across restarts; a scan launched from the GUI updates the table and the live topology graph; a saved profile round-trips (compose → save → reuse → run) entirely in the GUI.

---

## Phase 3 — Intelligence

**Goal:** Turn raw scan data into actionable signal — detection, change-tracking, and triage-grade vulnerability intelligence.
**Status:** Not started
**Features delivered:** F-012, F-013, F-014, F-015, F-016, F-017
**Deliverables:**
- [ ] `Detector` trait with native default detector
- [ ] Optional Nmap-backed detector (runtime shell-out to user binary, D-006)
- [ ] Native OS fingerprinting with an updatable corpus
- [ ] Scan diff + baseline designation + deviation view
- [ ] CVE matching (NVD/OSV) with EPSS + CISA KEV enrichment and composite risk score
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

<!--
When a phase completes, set its Status to "Complete (YYYY-MM-DD)" and tick its deliverables.
Do not delete completed phases — the historical sequence is itself documentation.
-->
