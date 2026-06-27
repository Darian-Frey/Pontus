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

- A root `Makefile` wrapping the build / `setcap` / run loop (`make build`/`cap`/`gui`/`scan`).
- GUI interface design tiers (Minimum / Good / Great) added to the roadmap; the interface features were registered as F-029–F-035.

### Changed

- The scan diff keys on `(proto, port)` (`PortRef`), so `tcp/53` and `udp/53` are distinct findings.
- The stateless SYN sweep was rebuilt around `BatchSender` with set-based reply matching to scale to wide ranges.

### Fixed

- The KEV cache is now found under `sudo`: `default_cache_dir` prefers the invoking user's cache (`/home/$SUDO_USER/.cache/pontus`) so a catalogue cached by `intel update` (run as the user) is used by a privileged `scan --assess-vulns` (BUG-008).
- Vulnerability assessment is no longer silent: each assessment prints `vulns <port>: <product> <version> → N CVE(s)`, and an NVD lookup error is reported instead of being swallowed to an empty result (BUG-009).
- The risk view's per-host CVE list is deduped by CVE in `risk_ranked`, so a product on multiple ports (e.g. 80 and 443) no longer lists each CVE twice or inflates the count (IMP-012).

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
