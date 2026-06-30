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
**Priority:** Should · **Status:** Done (core + CLI; D-011)
Native, community-updatable fingerprint corpus. Family-level guess from passive signals (p0f-style, no active probes) — the SYN-ACK's TCP-option layout (the strongest discriminator: Linux `MSTNW` vs Windows `MNWNNS` vs macOS), initial TTL, window and DF bit, plus volunteered service-banner OS tokens — scored against a clean-room corpus that layers a user JSON file over built-in defaults (C-001; never `nmap-os-db`). `pontus-cli scan` records the guess; `--os-corpus <path>` adds signatures without a rebuild. An optional `--os-detector nmap` backend shells out to the user's own `nmap -O` for a version-range guess (D-006-style, no bundled data). **Acceptance:** correctly buckets a handful of reference OSes by family; corpus is updatable without a rebuild.

### F-014 Scan diff & baselines
**Priority:** Must · **Status:** Not started
Diff any two scans; designate baselines; show deviation. **Acceptance:** opening a port between scans surfaces as an explicit "opened" change against baseline.

### F-015 CVE intelligence with EPSS + KEV
**Priority:** Must · **Status:** Not started
Match detected versions to NVD/OSV; enrich with EPSS and CISA KEV; composite a per-host risk score (C-002). **Acceptance:** a host with a KEV-listed vulnerable service sorts above a host with only a high-CVSS, low-EPSS issue.

### F-016 TLS/SSL inspection
**Priority:** Should · **Status:** Done (core + CLI; D-012)
Cert chain, expiry, weak ciphers, SNI, certificate-transparency cross-reference. A clean-room, pure-Rust prober (`tls` module, no OpenSSL): enumerates protocols SSLv3–TLS 1.3, probes weak-cipher acceptance, and captures + inspects the certificate (expiry, self-signed, weak signature/key, SAN/hostname). `pontus-cli tls <host>` reports it. CT cross-reference and full TLS 1.3-only cert capture are follow-ups. **Acceptance:** flags an expired cert and a weak cipher suite on a test endpoint — met, live-verified against badssl.com.

### F-017 HTTP tech fingerprinting
**Priority:** Could · **Status:** Done (core + CLI)
Wappalyzer-style stack identification from headers/markup. The `webtech` module identifies servers, languages, frameworks, CMSes, JS libraries, CDNs and analytics from response headers (`Server`, `X-Powered-By`, `Set-Cookie`, CDN markers), the `<meta generator>` tag and tell-tale paths/scripts — with versions where exposed. Clean-room signature set (C-001; not derived from Wappalyzer's dataset), reusing the existing `ureq` client, and extensible at runtime via a `--web-corpus <path>` JSON file layered over the built-in defaults (IMP-011, mirroring the OS corpus). `pontus-cli http <host>` reports it, scope-enforced. **Acceptance:** identifies server, framework and common front-end libraries on a reference site — met, live-verified (wordpress.org → nginx + WordPress 7.1; python.org → nginx + jQuery + Fastly).

### F-018 Monitoring daemon
**Priority:** Should · **Status:** Done (core)
`pontus-daemon` running scheduled rescans and persisting results. A TOML config of jobs (targets/scope/ports/interval + scan options) drives one timer per job; each run shells out to the capability-granted `pontus-cli scan` (D-008), so results land as ordinary append-only observations (D-007) and scans serialise through a single-writer lock. `--once` runs every job a single time (config check / cron use). **Acceptance:** a scheduled rescan runs unattended and writes observations to the store. ✅ (live: a daemon-driven loopback scan wrote a durable asset + observation).

### F-019 Alert rules & delivery
**Priority:** Should · **Status:** Done
Rules ("notify if port 22 opens on any server") evaluated by the daemon against drift after each scheduled scan, with delivery to desktop/webhook/Slack/Discord. Matching is headless (`alert::evaluate` over the scan diff — conditions `port_opened`/`port_closed`/`host_new`/`host_vanished`/`host_changed`/`address_moved`, with port/proto filters); "exactly once" falls out of diffing consecutive scans (a change appears in the diff once). Delivery lives in the daemon: `log`, `desktop` (notify-send), generic `webhook`, `slack`/`discord` (webhook shapes), and `email` (SMTP via lettre with rustls — starttls/implicit-tls/plaintext, optional auth). All five channels ship. **Acceptance:** a matching change fires exactly one alert via a configured channel. ✅ (live: a newly-opened port fired one alert delivered over both a webhook and email, the prior/identical scans firing none).

### F-020 Multi-language plugin system
**Priority:** Should · **Status:** Done
Stable `Finding` API; runners for Python (pyo3, trusted), Lua (mlua, built-ins), WASM (wasmtime, untrusted) (D-003). The `pontus-plugins` crate holds the serde-driven contract (`Finding`/`Severity`/`Target`/`TargetPort`), the `PluginRunner` trait + `PluginHost` (routes a plugin to its language's runner, stamps the producing plugin's name), and all three runners. **Lua** (mlua): plugins define `check(target)` and return finding tables, decoded via serde; curated, filesystem-free stdlib (base + table/string/math/coroutine, no io/os/package/debug) + memory limit (D-003: lightweight built-ins). **WASM** (wasmtime): the untrusted tier, run with **no host imports at all** — a module physically cannot touch the filesystem/network and one that even *imports* a WASI call fails to instantiate; fuel bounds CPU (runaway loops trap) and a memory cap bounds growth. ABI: guest exports `memory` + `run(target_ptr, target_len) -> i64` (packed result ptr/len) and optionally `alloc`; `.wasm` or `.wat` accepted. **Python** (pyo3): the trusted, full-power tier (deliberately *not* sandboxed) — a `check(target)` taking a dict and returning finding dicts, with JSON as the interchange (`json.loads`/`json.dumps`). Opt-in behind the `python` Cargo feature as it links libpython, so default builds stay Python-free. **Acceptance:** the same trivial plugin runs under each runner and returns structured findings; the WASM plugin cannot touch the filesystem. ✅ — the same telnet-detection plugin runs under Lua and Python (target-aware) and the WASM runner is sandbox-proven (WASI-import rejection + fuel trap); a target-aware compiled WASM guest awaits the F-021 SDK. Wired into scanning: `pontus-cli scan --plugins <dir>` loads plugins by extension (`.lua`/`.wasm`/`.wat`/`.py`), runs them against each up host (a `Target` built from the host's observed ports/services), and persists findings to a `findings` store table; `pontus-cli findings` lists them. In the GUI the New-scan dialog has a Plugins directory field and **View ▸ Plugin findings…** shows a scan's findings (over `pontus_findings_json`).

### F-021 First-party plugins
**Priority:** Could · **Status:** In progress (starter plugins shipped)
SMB share enumeration, SNMP OID walk, SSH host-key fingerprint, HTTP header audit. **Acceptance:** each ships, is documented, and returns findings against a test target. First-party Lua plugins now ship in `crates/pontus-plugins/plugins/` and are documented in its README: `cleartext-services.lua` (flags HTTP/FTP/Telnet/POP3/IMAP/SNMP/LDAP/VNC/r-services in the clear) and `exposed-discovery.lua` (UPnP/SSDP, mDNS, NetBIOS, WS-Discovery, IPP). Clean-room (well-known-port knowledge, C-001), unit-tested against synthetic targets. **Host-capability model (done):** plugins can now *actively probe* through host-mediated, scope-enforced capabilities — never ambient network access (preserves D-003). The host hands a plugin a `HostCapabilities` object; the Lua runner exposes it as `pontus.http_get(url)` (scope-checked by resolved IP before any connection, F-007). Probing plugins so far: `http-header-audit.lua` (missing HSTS/CSP/X-Content-Type-Options/clickjacking defences + software disclosure, via `pontus.http_get`) and `snmp-info.lua` (SNMP readable with a default community + the system info it discloses, via a clean-room SNMP v2c GET capability `pontus.snmp_get` over UDP 161 — dependency-free BER codec, C-001). **Remaining:** SSH host-key fingerprint and SMB enumeration (shell-out capabilities to the user's `ssh-keyscan`/`smbclient`, D-006 — chosen approach), and exposing capabilities to the WASM tier (a mediated host import).

### F-022 Credentialed scanning
**Priority:** Could · **Status:** Done (SSH; SNMP to come)
Optional SSH/SNMP using *user-supplied* credentials for inventory depth (never guessed — see non-goals). **Acceptance:** with valid SSH credentials, gathers installed-package inventory from a Linux host. ✅ SSH is done: the `cred` module shells out to the user's own `ssh` (and `sshpass` for password auth), the "use the user's tool" posture of D-006 — no SSH/crypto dependency is pulled in, and the user's config/agent/`known_hosts` apply. A single read-only remote command reports the OS (`/etc/os-release`) and the installed-package list (dpkg/rpm/pacman/apk), parsed into structured packages. `pontus-cli ssh-inventory <host> --user <u> [--key …|--password] [--scope …]` is scope-enforced (F-007), records an observation (SSH up + OS) and the packages against the resolved asset (a `packages` store table), and `pontus-cli packages` lists them. Passwords come from `PONTUS_SSH_PASSWORD`, never the command line. **Credentialed CVE matching** (F-022 + F-015): `ssh-inventory --assess-vulns` (or `--assess-packages a,b,c`) matches installed package versions to CVEs via the existing intel layer — version-accurate from the *installed* version, not a network banner. Distro versions are normalised (epoch/revision stripped, `1:8.9p1-3ubuntu0.10` → `8.9p1`) so they match NVD's upstream versions; results are recorded as host-level vulns and flow into `pontus-cli risk` / the GUI risk view. Bounded to a built-in set of common network-service products (or the explicit `--assess-packages` list) so a multi-thousand-package host doesn't flood the NVD API. Live-verified: OpenSSH 8.9p1 → 13 CVEs, nginx 1.18.0 → 6, ranked fix-first. **Remaining:** SNMP (OID walk), and whole-inventory matching via distro security advisories (OVAL/DSA/USN) for coverage beyond the network-service set.

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

### F-029 Inventory search & filtering
**Priority:** Must · **Status:** Not started
Free-text search and column filters over the asset inventory (identity, IP, hostname, service/port, up/down). The workhorse interaction of an asset-centric GUI. **Acceptance:** typing a term narrows the table live; filtering by an open port shows only the hosts exposing it.

### F-030 Saved views / smart filters
**Priority:** Should · **Status:** Not started
Named, reusable filter sets layered on F-029 — e.g. "port 22 open", "new since baseline", "SNMP-exposed". **Acceptance:** a user composes a filter, saves it, and reapplies it across sessions.

### F-031 Overview dashboard
**Priority:** Should · **Status:** Not started
A breadth-first summary home: total assets, up/down, new-since-baseline, most-exposed services, recent drift. **Acceptance:** the dashboard reflects the current store and each figure drills through to the corresponding filtered inventory view.

### F-032 Asset tags, notes & ownership
**Priority:** Should · **Status:** Not started
Single-user annotations — tags, free-text notes and an owner — attached to durable assets (distinct from the multi-user/RBAC candidate below). **Acceptance:** a tag/note/owner set on an asset persists across scans and restarts and is filterable.

### F-033 Time-travel view
**Priority:** Should · **Status:** Not started
A timeline control to view the estate's state at any past scan and step or animate change over time; the visual face of the observation history (extends F-014). **Acceptance:** scrubbing to an earlier scan shows the inventory and each host's state as observed at that point.

### F-034 Per-asset risk timeline
**Priority:** Could · **Status:** Not started
Per-asset history of exposure and risk (open services, CVE/risk score from F-015) charted across scans. **Acceptance:** an asset's detail view shows how its composite risk score changed between scans.

### F-035 Command palette / keyboard workflow
**Priority:** Could · **Status:** Not started
A keyboard-driven command palette for navigation and actions (run a scan, apply a filter, jump to an asset) for power users. **Acceptance:** the common actions are reachable from the palette without the mouse.

### F-036 Local network configuration
**Priority:** Could · **Status:** Done (core + CLI + GUI)
Show the host Pontus runs on — its interfaces (IP, MAC, netmask) and listening ports — as "self" info distinct from the asset model. `netinfo` module (interfaces via `pnet`, listening ports from `/proc/net`), FFI `pontus_local_config_json`, `pontus-cli netinfo`, and a GUI view (View ▸ Local network config, Ctrl+L). **Acceptance:** reports this machine's addresses and exposed ports.

### F-037 External CVE references
**Priority:** Could · **Status:** Done (GUI)
Each CVE in the risk view links to its authoritative detail page: double-clicking a CVE opens `https://nvd.nist.gov/vuln/detail/<id>` in the default browser (`QDesktopServices`). **Acceptance:** double-clicking a CVE opens its NVD page.

## Candidate features (uncommitted)

- Passive recon ingestion (certificate-transparency logs, Shodan/Censys via user API keys)
- Multi-user shared asset DB with tagging, notes and ownership / RBAC
- ML-assisted OS fingerprinting to extend the native corpus
