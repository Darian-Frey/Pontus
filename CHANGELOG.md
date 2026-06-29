# Changelog

All notable changes to Pontus are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches
a first tagged release. Entries reference the feature (`F-NNN`), claim (`C-NNN`)
and decision (`D-NNN`) registers in [docs/VISION.md](docs/VISION.md) and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for traceability.

## [Unreleased]

No public release has been tagged yet. Phases 1 (Foundation) and 2 (GUI skeleton)
are complete and Phase 3 (Intelligence) is in progress; everything below is on
`main`, awaiting a first `0.1.0` tag.

### Added

#### Phase 4 — monitoring and plugins

- `pontus-plugins` crate — the plugin host (F-020, D-003), first slice. A stable, serde-driven data contract (`Finding`/`Severity`/`Target`/`TargetPort`), a `PluginRunner` trait and a `PluginHost` that routes a plugin to the runner for its language and stamps the producing plugin's name, plus the **Lua runner** (mlua): a plugin defines `check(target)` and returns finding tables, decoded back via serde. The Lua state is sandboxed to a curated, filesystem-free standard library (base + table/string/math/coroutine — no io/os/package/debug) with a memory limit. Example `plugins/telnet.lua`. WASM (wasmtime) and Python (pyo3) runners are still to come.
- Alert rules and delivery (F-019). After each scheduled scan the daemon diffs it against the previous scan of the same target range and evaluates rules (conditions `port_opened`/`port_closed`/`host_new`/`host_vanished`/`host_changed`/`address_moved`, with optional port/proto filters). Matching is headless in `pontus_core::alert` (`evaluate` over the diff); because a diff reports a change once, an alert fires exactly once per change, and the first scan of a range never alerts (no baseline). Delivery (in the daemon): `log`, `desktop` (notify-send), generic `webhook`, and `slack`/`discord` webhook shapes — failures are logged, never fatal. Email/SMTP is the one channel still to come. Config via `[[alert]]` rules + `[channels.*]` URLs (validated at startup).
- `pontus-daemon`: unattended scheduled rescans (F-018). A TOML config of jobs (targets/scope/interval plus the scan options that map to `pontus-cli scan` flags) drives one timer per job; each run shells out to the capability-granted CLI (D-008) so results land as ordinary append-only observations against the resolved assets (D-007), feeding drift/baseline/risk with no extra wiring. Scans serialise through a single-writer lock; `run_at_start` produces a baseline immediately; `--once` runs every job a single time (config check / cron). New `make daemon` target and `examples/pontus-daemon.toml`.

#### Cross-cutting

- The asset's MAC address is now shown explicitly in the GUI — a dedicated "MAC" column in the inventory and a "MAC:" line in the asset-detail panel (it reads "— (no MAC learned)" for IP-only hosts). Previously the MAC was only implicit in the Identity column of MAC-anchored rows. Backed by a new `mac` field on `AssetSummary` (flows through `pontus_assets_json`).
- Local network configuration view (`netinfo` module): this machine's interfaces (IP/MAC/netmask) and listening ports, over FFI `pontus_local_config_json`, the `pontus-cli netinfo` command, and a GUI view (View ▸ Local network config, Ctrl+L). "Self" info, distinct from the asset model — interfaces via `pnet`, listening ports from `/proc/net` (F-036).
- External CVE references: double-clicking a CVE in the risk view opens its NVD detail page in the default browser (F-037).

#### Phase 1 — native engine and asset store

- Cargo workspace with the headless `pontus-core` and the `pontus-cli` driver (F-005, D-001).
- SQLite `assets`/`observations`/`scans` store; observations are append-only, enforced by triggers (F-003, D-002, D-007).
- Host identity resolution — MAC → host key/cert → hostname → IP, with in-place promotion when a stronger signal appears (F-004, C-003).
- Unconditional scope enforcement with no allow-all or disable path, plus a scan audit log (F-007).
- Native host discovery — ARP and ICMP echo over IPv4 and IPv6, with an unprivileged TCP-connect fallback (F-001, D-004).
- Hybrid port scanning — a stateless raw SYN sweep feeding a stateful connect/banner deep pass (F-002, C-005); `raw::BatchSender` and per-/24 source caching make wide ranges fast.
- UDP scanning via connected sockets (open / closed / open|filtered), with clean-room DNS/NTP/SNMP/SSDP/mDNS probe payloads built from their RFCs, never from Nmap's corpus (F-002, C-001).
- Reverse-DNS resolution to fill the hostname identity tier (F-004).
- Scan diff — `diff::diff_observations` compares two scans by `asset_id`, proto-aware via `PortRef` (F-014).
- Traceroute and a topology `edges` store — ICMP echo with rising TTL, routers via Time Exceeded (F-009).
- Integration-test harness exercising the public API (store, identity, scope, diff, real-socket connect scan).

#### Phase 2 — GUI skeleton

- `pontus-ffi` C-ABI shim with a JSON read surface (assets, scans, asset history, diff, topology) plus a baseline write, and a hand-written `pontus.h` (D-001).
- Qt6 Widgets desktop frontend: a filterable asset inventory with a per-asset observation-history detail pane as the home screen (F-008).
- Scan-from-GUI — a New-scan dialog with a mandatory scope field and live output, run by shelling out to the privileged `pontus-cli` rather than scanning in-process (F-010, D-008).
- Saveable scan profiles persisted in `QSettings` (F-010).
- Drift view comparing two scans, colour-coded, with baseline designation the view defaults to (F-014).
- Service/port heatmap — a host × open-service grid, most-shared columns first, so shared exposure forms vertical bands (F-011).
- Force-directed topology graph (`View ▸ Topology`) rendering the traceroute edges, scanner pinned at the centre, with pan and zoom (F-009).

#### Phase 3 — intelligence

- Service/version detection behind a host-level `Detector` trait: `NativeDetector`, a clean-room banner grammar (SSH/HTTP/FTP/SMTP/POP3/IMAP) plus well-known-port fallback, never derived from `nmap-service-probes` (F-012, C-001).
- Optional `NmapDetector` that shells out to the user's own `nmap -sV` and parses its XML, never bundled (F-012, D-006/C-001); selected with `pontus-cli --detector nmap`.
- Vulnerability intelligence (F-015, C-002): the exploitation-weighted risk model (`intel::risk_score`/`band`, KEV → EPSS → CVSS), the CISA KEV catalogue and FIRST EPSS feeds, and NVD CVE matching by CPE applicability (`virtualMatchString`, for version-accurate results) with EPSS + KEV enrichment. Hybrid data delivery (D-009): KEV/EPSS cached locally, NVD queried on demand.
- `pontus-cli intel update`/`status`, `scan --assess-vulns` (stores matched CVEs in a `vulns` table), and `risk` (hosts ranked fix-first).
- GUI risk view — `View ▸ Risk / vulnerabilities…` (Ctrl+R): a master/detail triage queue over a shared `store::risk_ranked` and FFI `pontus_risk_json`, hosts worst-first with a per-host CVE breakdown (band, CVSS, EPSS, KEV badge), band-coloured (F-015).
- Native OS fingerprinting (`os` module): a passive, p0f-style family-level guess from a `StackSignature` read off the SYN-ACK — the TCP-option layout (Linux `MSTNW` vs Windows `MNWNNS` vs macOS, the strongest discriminator), initial TTL, window and DF bit — plus volunteered service-banner tokens and the ICMP echo-reply TTL for portless hosts. Scored against a clean-room `OsCorpus` (public IP-stack option orders/TTLs + host-emitted strings, never `nmap-os-db`); confidence blends signal agreement with evidence strength so a lone TTL caps at 0.5. `pontus-cli scan` records and prints it; `--os-corpus <path>` layers a user JSON file over the defaults, updatable without a rebuild (F-013, C-001, D-011; IMP-006). An example corpus ships at `examples/os-corpus.json`.
- Optional Nmap-backed OS detector (`os::NmapOsDetector` behind an `OsDetector` trait): `pontus-cli scan --os-detector nmap` shells out to the user's own `nmap -O` and parses the highest-accuracy `<osmatch>` for a version-range guess (e.g. "Linux 5.0 - 5.4"). Never bundled, never reads `nmap-os-db` itself (F-013, C-001, D-006/D-011); `-O` needs raw sockets, so run via sudo.
- TLS/SSL inspection (`tls` module, `pontus-cli tls <host>`): a clean-room, pure-Rust prober (no OpenSSL/crypto dependency) that hand-rolls `ClientHello`s and parses `ServerHello`/`Certificate` directly. Enumerates protocols SSLv3–TLS 1.3, probes weak-cipher acceptance, and captures + inspects the certificate (expiry, self-signed, weak signature/key, SAN/hostname). Scope-enforced (F-007); live-verified against badssl.com (F-016, C-001, D-012). Adds the `x509-parser` dependency.
- GUI surfaces the OS guess (IMP-004): an "OS" column in the asset inventory (the most-recent observation's `os_guess`, added to `AssetSummary` via a `json_extract` subquery) and in the per-asset observation history. Read-side over data the store already holds (F-013).
- Deep inspection folded into scans and the GUI (IMP-008/IMP-010): `pontus-cli scan --inspect` runs TLS inspection (F-016) on open TLS ports and web-tech fingerprinting (F-017) on open HTTP ports, recording a compact `TlsObservation`/`TechObservation` per port in the observation `state` (JSON, no migration). The GUI asset detail gains a "Deep inspection" panel showing the latest observation's TLS findings and detected technologies. Opt-in, since it adds handshakes/requests.
- HTTP technology fingerprinting (`webtech` module, `pontus-cli http <host>`): Wappalyzer-style stack identification from response headers (`Server`, `X-Powered-By`, `Set-Cookie`, CDN markers), the `<meta generator>` tag and body markers — servers, languages, frameworks, CMSes, JS libraries, CDNs and analytics, with versions where exposed. Clean-room signature set (not from Wappalyzer's dataset), reusing the existing `ureq` client; scope-enforced. Live-verified on wordpress.org/python.org (F-017, C-001). **Completes Phase 3.**

#### Tooling and documentation

- A root `Makefile` wrapping the build / `setcap` / run loop (`make build`/`cap`/`gui`/`scan`). `cap` is idempotent (re-applies `CAP_NET_RAW` only when missing) and `gui`/`scan` depend on it, so the workflow self-heals the capability a rebuild drops — GUI scans keep raw privilege without a manual re-cap (IMP-017).
- GUI interface design tiers (Minimum / Good / Great) added to the roadmap; the interface features were registered as F-029–F-035.

### Changed

- Vulnerability assessment sends an optional `NVD_API_KEY` (raising NVD's rate limit) and retries throttling (HTTP 403/429/503) with exponential backoff, plus a per-request timeout — so large `--assess-vulns` scans complete instead of dropping enrichment (IMP-002, fixes BUG-004).
- Web-tech signatures are now an updatable `WebCorpus` (mirroring `OsCorpus`): a `--web-corpus <path>` JSON file layers over the built-in defaults for `pontus-cli http` and `scan --inspect`, so coverage grows without a rebuild. Example at `examples/web-corpus.json` (F-017, IMP-011).
- The risk view marks version-less CVE matches as "product-wide" (vs "exact") — a new `vulns.version_matched` flag carried through `risk_ranked`/`pontus_risk_json` to a Match column in the GUI (amber + tooltip) and a "(product-wide)" marker in the CLI — so the inherent over-reporting of version-less matching is visible rather than silently inflating counts (IMP-003, surfaces BUG-002).
- The scan diff keys on `(proto, port)` (`PortRef`), so `tcp/53` and `udp/53` are distinct findings.
- The stateless SYN sweep was rebuilt around `BatchSender` with set-based reply matching to scale to wide ranges.
- `--ports` (and `--udp-ports`) now accept ranges and mixed specs — `80,443,8000-8100`, `1-1024`, `-` for all of 1–65535 — de-duplicated and sorted; plus a `--top-ports <N>` preset over a curated clean-room common-ports list, unioned with `--ports`. Broad scanning is now a one-liner instead of a hand-typed list (F-002, IMP-013).
- The GUI New-scan dialog now exposes the richer scan options — a Top-ports field, a Detector dropdown (native / nmap), and Assess-vulnerabilities / Deep-inspect (TLS+HTTP) checkboxes — threaded into the shelled-out command and saved with profiles, so a GUI-launched scan can be as thorough as a CLI one and populate the risk/heatmap/deep-inspection views (F-010, IMP-014).
- `--assess-vulns` now also assesses the web technologies found by `--inspect`, not just the service detector's products — so the clean-room native detector plus `--inspect` matches web-server CVEs (e.g. nginx) without needing `--detector nmap` (F-015, IMP-015).

### Fixed

- One physical host no longer appears twice in the inventory. A host first seen via ARP (MAC-anchored) and later seen via ICMP only — a sighting carrying no MAC — previously forked a second, IP-anchored asset; the bare-IP fallback in identity resolution now attaches a genuinely MAC-less sighting to whichever asset already lives at that address (most-recent-first, so a recycled lease follows its present tenant), while a sighting with a new, unmatched MAC is still treated as a distinct host (BUG-012, F-004, C-003). Prevention only — append-only observations (D-007) mean pre-existing duplicates can't be merged retroactively.
- The KEV cache is now found under `sudo`: `default_cache_dir` prefers the invoking user's cache (`/home/$SUDO_USER/.cache/pontus`) so a catalogue cached by `intel update` (run as the user) is used by a privileged `scan --assess-vulns` (BUG-008).
- Vulnerability assessment is no longer silent: each assessment prints `vulns <port>: <product> <version> → N CVE(s)`, and an NVD lookup error is reported instead of being swallowed to an empty result (BUG-009).
- The risk view's per-host CVE list is deduped by CVE in `risk_ranked`, so a product on multiple ports (e.g. 80 and 443) no longer lists each CVE twice or inflates the count (IMP-012).
- The service/port heatmap is now scoped to a single scan (a selector, defaulting to the latest) over a new `pontus_observations_json` FFI, instead of mixing each host's latest observation across scans with different port coverage — which made the grid look inconsistent (BUG-010).
- The heatmap distinguishes confirmed-open ports (green) from UDP `open|filtered` / no-reply (amber), with a legend and tooltips, so unconfirmed UDP no longer reads as solid exposure (IMP-016).
- Wide scans no longer abort on `ENOBUFS`: the raw-socket send path treats a full transmit queue (os error 105) as transient backpressure — pacing and retrying rather than failing — so a `/24 × ~100 ports` sweep completes instead of erroring out (BUG-011).
- Service banners no longer carry trailing dots from a stripped CRLF (`scan::stateful::sanitise`).
- Muted note text is now theme-adaptive (`applyMutedText`) instead of `palette(mid)`, which was unreadable on dark themes.
- The topology graph settles its layout before drawing — no on-screen jitter — and drag-to-pan / scroll-to-zoom now work.
- The GUI build resolves `libpontus_ffi` directly from `PONTUS_TARGET_DIR` instead of via `find_library`, whose cache is independent of the target dir — configuring debug then release no longer keeps linking the stale debug `.so`.

### Decisions

- **D-006** — own the packet engine, make deep detection pluggable (supersedes D-005).
- **D-007** — the asset inventory is the architectural core; scans are append-only observation events.
- **D-008** — the GUI shells out to the privileged CLI for scans rather than holding `CAP_NET_RAW` itself.
- **D-009** — hybrid vulnerability-data delivery: cache the small KEV/EPSS feeds locally for offline, testable scoring; query the NVD API on demand for CVE matching.
- **D-010** — adopt in-repo `BUGS.md` / `IMPROVEMENTS.md` Tier-2 registers (`BUG-NNN` / `IMP-NNN`) over an external tracker.
- **D-011** — OS fingerprinting is passive, family-level and corpus-driven (clean-room), not active stack fingerprinting or a bundled OS database.
- **D-012** — TLS/SSL inspection is a pure-Rust, clean-room prober (hand-rolled `ClientHello`/`ServerHello` parsing + `x509-parser`), not OpenSSL — keeping the engine cross-platform for the Windows pipeline.

[Unreleased]: https://github.com/Darian-Frey/Pontus
