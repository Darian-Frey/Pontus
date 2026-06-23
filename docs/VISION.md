> **Status:** Active
> **Provenance:** Shane Hartley (architect); Claude (document generation, primary auditor) — 2026-06-22
> **Last reviewed:** 2026-06-22
> **Why this status:** Vision and feature scope agreed at concept stage; acceptance criteria are first-draft and will tighten as Phase 1 exposes reality.

# Vision

## The problem

Nmap is the field standard and will remain so for raw scanning — but it is a *point-in-time* tool. It tells you the state of a network the moment you ran it, emits text or XML, and forgets everything. It has no concept of a host as a durable entity, no built-in change tracking, no asset inventory, and no notion that the same machine seen on two different IPs across two scans is the same machine. Its official GUI, Zenmap, is effectively unmaintained (C-004), so the modern, visual, stateful experience simply does not exist.

Pontus exists to close that gap. The reframing is deliberate: **Pontus is an asset-inventory and change-monitoring platform that happens to scan**, not a scanner that happens to keep some history. Everything that makes it more useful than Nmap — drift detection, baselines, time-travel, alerting, actionable CVE triage — depends on that inversion, and the architecture is built around it (D-007).

## Target users

Network operators and security engineers who manage a known estate and need to detect change and drift; home-lab and prosumer users who want a maintained, GUI-native successor to Zenmap; and anyone running periodic authorised scans who currently glues Nmap to a pile of scripts to get an asset picture.

## What Nmap does, and where Pontus goes further

Nmap's strengths are host discovery, a deep catalogue of port-scan techniques (SYN, connect, UDP, the stealth scans, idle/zombie, ACK firewall-mapping), service/version detection against a ~11k-signature database, OS fingerprinting, the NSE Lua scripting engine, and mature timing/evasion controls. Pontus reimplements the parts that must be owned and builds the rest as genuinely new capability:

1. **Asset inventory with drift detection** — the headline. Persistent history; diffs surfacing new/vanished hosts, opened/closed ports and version drift; designated baselines; a time-travel view across scans.
2. **Actionable vulnerability intelligence** — CVE matching enriched with EPSS (exploitation probability) and CISA KEV (known-exploited), composited into a per-host risk score, so a subnet sorts by *fix this first* rather than dumping raw CVE lists (C-002).
3. **Hybrid speed** — a stateless masscan-style wide sweep feeds a stateful Nmap-style deep pass; fast and thorough rather than one or the other (C-005).
4. **Visualisation that earns its place** — live force-directed topology graph, service/port heatmaps, fingerprint clustering, all over a filterable asset table.
5. **Continuous monitoring** — a daemon running scheduled rescans with configurable alert rules and delivery to desktop/email/webhook/chat.
6. **Deeper, modern detection** — TLS inspection, HTTP tech fingerprinting, optional credentialed scanning for true inventory depth.
7. **A sandboxed multi-language plugin ecosystem** — Python (pyo3), Lua (mlua), and untrusted WASM (wasmtime).
8. **Pipeline-native integration** — JSON-first output (Nmap's glaring gap), SARIF for CI, a REST API, and Nmap XML *import* as a migration bridge.
9. **Responsible-use guardrails as a first-class feature** — mandatory scope enforcement and an audit log, so authorised, scoped scanning is the easy default rather than an afterthought.

## Design principles

- **The asset is the noun; the scan is the verb.** Durable entities first, scan runs are events that update them.
- **Own what gives advantage, borrow what's curated.** Own the packet engine (it's where hybrid speed lives); make deep detection pluggable rather than reinventing 25 years of fingerprint curation on day one (D-006).
- **Useful beats exhaustive.** "Better than Nmap" means better triage and better continuity, not a longer feature list for its own sake.
- **Scoped by default.** A tool that can map a network can disrupt one. Scope enforcement and audit logging are not optional extras.
- **The core is headless.** CLI and GUI are both clients of `pontus-core`; nothing GUI-only lives in the engine.

## Out of scope (non-goals)

- **Not an exploitation framework.** Pontus detects and triages; it does not weaponise. No exploit payloads, no Metasploit-style post-exploitation.
- **Not a credential brute-forcer.** Credentialed scanning (F-022) uses *user-supplied* credentials for inventory depth; Pontus does not guess or crack them.
- **Not a packet-capture / IDS suite.** It is an active inventory tool, not Wireshark or Suricata.
- **Not bundling Nmap.** The optional Nmap-backed detector shells out to the user's own install; Nmap is never a dependency or a bundled artefact (D-006).

---

## Constraints & load-bearing claims (C-NNN)

Append-only. These are the assumptions the design rests on; if one is falsified, the linked decisions are in play.

### C-001 Nmap's fingerprint data is restrictively licensed
**Status:** Accepted
`nmap-service-probes` and `nmap-os-db` ship under the Nmap Public Source Licence (NPSL), a GPL-derivative with commercial-redistribution restrictions. Bundling those files would create derivative-work entanglement. **Consequence:** Pontus must not vendor Nmap data; deep detection is either native (clean-room) or shells out to the user's own Nmap binary at runtime. Drives D-006.

### C-002 Exploitation likelihood, not raw severity, drives triage
**Status:** Accepted
CVSS severity alone over-reports urgency. EPSS (probability of exploitation in the wild) and CISA KEV (confirmed known-exploited) are the signals that make a CVE list actionable. **Consequence:** the intelligence layer must ingest EPSS + KEV and composite them into risk, not just match CVE IDs. Drives F-015.

### C-003 IP addresses are not stable host identifiers
**Status:** Accepted
DHCP and cloud churn reassign IPs constantly; the same host appears on different addresses across scans, and different hosts reuse the same address. **Consequence:** durable identity needs a resolution hierarchy (MAC → stable host key / TLS cert fingerprint → hostname → IP). Drives D-007, F-004.

### C-004 Zenmap is effectively unmaintained
**Status:** Accepted
Nmap's official GUI has seen no meaningful modernisation for years. **Consequence:** a maintained, GUI-native tool has an open niche; the GUI is a primary differentiator, not a wrapper afterthought.

### C-005 Stateless and stateful scanning are complementary
**Status:** Accepted
Masscan-style stateless async scanning is fast but shallow; Nmap-style stateful scanning is careful but slow. They are not competitors. **Consequence:** a hybrid pipeline (wide stateless sweep → targeted stateful deep pass) captures both. Drives F-002, and is only achievable on an owned packet engine (D-006).

---

## Feature register (F-NNN)

Append-only; withdrawn features get `Status: Withdrawn`, never deletion. MoSCoW priorities. Phase mapping lives in [ROADMAP.md](ROADMAP.md).

### F-001 Native host discovery
**Priority:** Must · **Status:** Not started
ARP (local), ICMP echo/timestamp/netmask, TCP SYN/ACK ping, UDP ping. **Acceptance:** discovers live hosts on a /24 with results matching Nmap host discovery on the same subnet within a small, explained delta.

### F-002 Hybrid port scanning
**Priority:** Must · **Status:** Not started
Stateful SYN/connect/UDP scans *and* a stateless async wide sweep, with the sweep feeding the deep pass. **Acceptance:** stateless sweep of a /16 completes in seconds; live ports are handed to the stateful pass; combined results match a full Nmap SYN scan on a reference host.

### F-003 Asset/observation data model
**Priority:** Must · **Status:** Not started
Persistent SQLite store with durable `assets` and append-only `observations` (D-007). **Acceptance:** two scans of the same host produce one asset and two observation sets; no duplicate asset rows.

### F-004 Host identity resolution
**Priority:** Must · **Status:** Not started
Resolve identity by MAC → host key / TLS cert fingerprint → hostname → IP (C-003). **Acceptance:** a host that changes IP between scans (forced DHCP lease change) resolves to the same asset.

### F-005 CLI front-end
**Priority:** Must · **Status:** Not started
`pontus-cli` as a full client of `pontus-core`. **Acceptance:** scan, list assets, and diff are all driveable from the CLI with no GUI present.

### F-006 IPv6-native scanning
**Priority:** Must · **Status:** Not started
IPv6 discovery and scanning from the first release, not retrofitted (D-004). **Acceptance:** dual-stack host is discovered and scanned over both families in one run.

### F-007 Scope enforcement & audit log
**Priority:** Must · **Status:** Not started
Mandatory authorised-range declaration; packets outside scope are refused. Every scan is logged (targets, time, operator). **Acceptance:** a scan targeting an out-of-scope address is blocked before any packet is sent and the attempt is recorded.

### F-008 GUI asset inventory home
**Priority:** Must · **Status:** Not started
Qt6 shell whose home screen is the asset table + detail pane; "run a scan" is an action that updates it. **Acceptance:** inventory persists across app restarts; selecting a host shows its observation history.

### F-009 Live topology graph
**Priority:** Should · **Status:** Not started
Force-directed graph built from traceroute hop data, nodes appearing as the scan runs. **Acceptance:** graph renders a multi-subnet scan with edges from real hop data, updating live.

### F-010 Scan profiles & command builder
**Priority:** Should · **Status:** Not started
GUI-driven scan configuration with saveable profiles; no CLI knowledge required. **Acceptance:** a user composes, saves, reuses and runs a profile entirely from the GUI.

### F-011 Service/port heatmap
**Priority:** Could · **Status:** Not started
Subnet-wide heatmap of services/ports to spot shared exposure. **Acceptance:** hosts running the same service are visually grouped across a /24.

### F-012 Pluggable service/version detection
**Priority:** Must · **Status:** Not started
`Detector` trait with a native default detector and an optional Nmap-backed shell-out detector (D-006). **Acceptance:** native detector identifies common services; switching to the Nmap backend (if installed) improves coverage without code change.

### F-013 OS fingerprinting
**Priority:** Should · **Status:** Not started
Native, community-updatable fingerprint corpus. **Acceptance:** correctly buckets a handful of reference OSes by family; corpus is updatable without a rebuild.

### F-014 Scan diff & baselines
**Priority:** Must · **Status:** Not started
Diff any two scans; designate baselines; show deviation. **Acceptance:** opening a port between scans surfaces as an explicit "opened" change against baseline.

### F-015 CVE intelligence with EPSS + KEV
**Priority:** Must · **Status:** Not started
Match detected versions to NVD/OSV; enrich with EPSS and CISA KEV; composite a per-host risk score (C-002). **Acceptance:** a host with a KEV-listed vulnerable service sorts above a host with only a high-CVSS, low-EPSS issue.

### F-016 TLS/SSL inspection
**Priority:** Should · **Status:** Not started
Cert chain, expiry, weak ciphers, SNI, certificate-transparency cross-reference. **Acceptance:** flags an expired cert and a weak cipher suite on a test endpoint.

### F-017 HTTP tech fingerprinting
**Priority:** Could · **Status:** Not started
Wappalyzer-style stack identification from headers/markup. **Acceptance:** identifies server, framework and common front-end libraries on a reference site.

### F-018 Monitoring daemon
**Priority:** Should · **Status:** Not started
`pontus-daemon` running scheduled rescans and persisting results. **Acceptance:** a scheduled rescan runs unattended and writes observations to the store.

### F-019 Alert rules & delivery
**Priority:** Should · **Status:** Not started
Per-profile rules ("notify if port 22 opens on any server") with delivery to desktop/email/webhook/Slack/Discord. **Acceptance:** a matching change fires exactly one alert via a configured channel.

### F-020 Multi-language plugin system
**Priority:** Should · **Status:** Not started
Stable `Finding` API; runners for Python (pyo3, trusted), Lua (mlua, built-ins), WASM (wasmtime, untrusted) (D-003). **Acceptance:** the same trivial plugin runs under each runner and returns structured findings; the WASM plugin cannot touch the filesystem.

### F-021 First-party plugins
**Priority:** Could · **Status:** Not started
SMB share enumeration, SNMP OID walk, SSH host-key fingerprint, HTTP header audit. **Acceptance:** each ships, is documented, and returns findings against a test target.

### F-022 Credentialed scanning
**Priority:** Could · **Status:** Not started
Optional SSH/SNMP using *user-supplied* credentials for inventory depth (never guessed — see non-goals). **Acceptance:** with valid SSH credentials, gathers installed-package inventory from a Linux host.

### F-023 Reporting & export
**Priority:** Should · **Status:** Not started
HTML/PDF reports, SARIF 2.1, and JSON-native output. **Acceptance:** a scan exports to all three; SARIF validates against the 2.1 schema.

### F-024 REST API
**Priority:** Could · **Status:** Not started
Automatable HTTP API over the core. **Acceptance:** a scan can be launched and its results retrieved entirely over HTTP.

### F-025 Nmap XML import
**Priority:** Should · **Status:** Not started
Parse `.nmap` XML into the asset store as a migration bridge. **Acceptance:** an existing Nmap XML imports as assets + observations with no data loss in mapped fields.

### F-026 Plugin registry
**Priority:** Could · **Status:** Not started
Git-hosted registry, browsable in-app, one-click install, signature verification. **Acceptance:** a signed plugin installs from the registry; an unsigned one is refused.

### F-027 Enrichment (ASN/geo/WHOIS/cloud)
**Priority:** Could · **Status:** Not started
Tag assets with ASN, geo, WHOIS and cloud-provider data. **Acceptance:** a public-IP asset is tagged with its ASN and cloud provider where applicable.

### F-028 Windows support
**Priority:** Should · **Status:** Not started
Tested Windows build of core + GUI. **Acceptance:** core and GUI build and pass the smoke suite on Windows.

## Candidate features (uncommitted)

- Passive recon ingestion (certificate-transparency logs, Shodan/Censys via user API keys)
- Multi-user shared asset DB with tagging, notes and ownership / RBAC
- ML-assisted OS fingerprinting to extend the native corpus
