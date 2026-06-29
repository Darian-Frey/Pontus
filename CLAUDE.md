# CLAUDE.md

## Project

Pontus is a GUI-native network scanner and asset-inventory platform — a modern, stateful successor to Nmap/Zenmap. Phase 1 is under way: the document set is complete and the native Rust core + CLI now build and run.

## Current state

- `docs/VISION.md`: complete. Problem, differentiation, design principles, non-goals, `C-NNN` claims register (C-001–C-005), `F-NNN` feature register (F-001–F-035; F-029–F-035 are the GUI interface features).
- `docs/ARCHITECTURE.md`: complete. Three-tier design, hybrid scan pipeline, asset/observation data model, invariants, `D-NNN` decision register (D-001–D-007; D-005 superseded by D-006).
- `docs/ROADMAP.md`: complete. Five phases mapping to the feature register.
- `README.md`: complete. Status header, intended quick-start/structure, documentation map.
- `crates/pontus-core`, `crates/pontus-cli`, `crates/pontus-ffi`, `crates/pontus-daemon`: exist and build (Cargo workspace). `gui/`: Qt6 shell exists and builds (CMake, links `pontus-ffi`). `crates/pontus-plugins` exists with all three runners — Lua, WASM, and Python (pyo3, behind the opt-in `python` feature) — wired into `pontus-cli scan --plugins`. F-020 is complete.
- `CHANGELOG.md` (Keep a Changelog) and `BUILD.md` now exist at the root. `DECISIONS.md`/`FEATURES.md` are deliberately folded into ARCHITECTURE/VISION (the documented divergence — see "Conventions"); split them only if the registers grow unwieldy.

### Phase 1 progress

- **Done:** workspace scaffold; `pontus-core` `assets`/`observations`/`scans` schema with trigger-enforced append-only observations (F-003); identity resolution MAC → host-key → hostname → IP with promotion (F-004); unconditional scope enforcement + audit log (F-007); native host discovery — ARP + ICMP echo over IPv4/IPv6 with privilege fallback (F-001); hybrid scan pipeline — stateless SYN sweep → stateful connect/banner deep pass, shared raw-socket plumbing in `raw.rs` (F-002); scan diff — headless `diff::diff_observations` comparing two scans by `asset_id` (F-014 first cut); `pontus-cli` scan/assets/diff (F-005). Validated live on a reference /24: 7 hosts → 7 durable assets, stable across three re-scans; port scan of a reference host is an exact match with `nmap -sS`; drift surfaces opened/closed ports against a stable asset.
- **Refinements (all done):** rDNS fills the hostname tier (`rdns::reverse_lookup`, `--no-rdns`); UDP scanning via connected sockets (`scan::udp`, open/closed/open|filtered, `--udp-ports`) with clean-room protocol payloads (`scan::udp_probes`: DNS/NTP/SNMP/SSDP/mDNS, C-001); diff is proto-aware (`PortRef`, so `tcp/53` ≠ `udp/53`); the stateless sweep is batched for wide ranges (`raw::BatchSender`, per-/24 source cache). Validated live: router DNS/NTP/UPnP and host mDNS confirmed open with data.

### Phase 2 progress

- **Done:** `pontus-ffi` C-ABI shim (`pontus_open`/`assets_json`/`scans_json`/`asset_history_json`/`diff_json`/`string_free`; opaque handle; JSON across the boundary; hand-written `include/pontus.h`) — read surface only, D-001. `gui/` Qt6 Widgets shell (CMake, links `libpontus_ffi`): filterable asset table + per-asset observation-history detail pane (F-008); a New-scan dialog with mandatory scope + live output that shells out to the privileged `pontus-cli` (D-008, F-010 first cut); and a drift view (`View ▸ Drift / diff…`) comparing two scans — colour-coded new/vanished/changed hosts with opened/closed ports and IP moves, over `pontus_diff_json` (F-014 GUI side); and a service/port heatmap (`View ▸ Service heatmap…`) — a host × open-service grid, columns ordered most-shared first so shared exposure forms vertical bands (F-011). Verified live on a reference /24 (e.g. mDNS open across 6/7 hosts, SNMP on 2).
- **Also done:** saveable scan profiles in the New-scan dialog (QSettings, GUI-side; F-010); baseline designation (F-014) — store-level `meta` table + `set_baseline`/`baseline`, exposed over a new FFI **write** surface (`pontus_set_baseline`/`pontus_baseline`), with the drift view defaulting From to the baseline. The FFI write surface is now used for baseline metadata only; scanning still shells out to the CLI (D-008).
- **Topology data layer (F-009, done):** core `traceroute` (ICMP echo with rising TTL; routers via Time Exceeded, target via Echo Reply; `parse_icmp_v4_message`), an `edges` store table (`record_edge`/`edges_for_scan`), FFI `pontus_topology_json`, and a CLI traceroute pass recording `scanner → hop → … → host` edges (`--no-traceroute`/`--max-hops`). IPv4 only (v6 hop-limit is a follow-up). Validated live: a flat /24 yields a star of edges from the scanner to ICMP-echo-responsive hosts.
- **Tooling:** a root `Makefile` wraps the build/setcap/run loop (`make build`/`cap`/`gui`/`scan`).
- **Topology graph (F-009, done):** a Qt `QGraphicsView` force-directed graph (`View ▸ Topology…`) rendering `pontus_topology_json` — the layout settles synchronously before drawing (no jitter), the scanner is pinned at the centre, with drag-pan and scroll-zoom. **Phase 2 is complete** (all of F-008/F-009/F-010/F-011).

### Phase 3 progress

- **Done:** service/version detection behind a host-level `Detector` trait (F-012). `detect::NativeDetector` — clean-room (banner grammar for SSH/HTTP/FTP/SMTP/POP3/IMAP + well-known-port fallback, never `nmap-service-probes`, C-001). `detect::NmapDetector` — optional shell-out to the user's own `nmap -sV`, parsing its XML via `roxmltree` (never bundled, D-006); selected with `pontus-cli --detector nmap`. Observations carry structured `service`/`version`. Verified live with both backends.
- **Intelligence core (F-015, in progress):** `intel` module with the C-002 exploitation-weighted risk model (`risk_score`/`band`/`host_risk` — KEV dominates, then EPSS, then CVSS, unit-tested), the CISA KEV catalogue (fetch/cache/query via `pontus-cli intel update`/`status`), and the EPSS parser. Hybrid data delivery (D-009): KEV/EPSS cached locally so scoring is offline + testable; NVD matching queries the API on demand. `ureq` for fetch; nothing vendored. Live-verified: fetched 1629 known-exploited CVEs. **Remaining slice:** NVD CVE matching for detected product/version, EPSS enrichment, scan wiring (services → vulns → per-host risk), and a risk-ranked view.
- **F-015 (done):** NVD CVE matching by **CPE applicability** (resolve product→CPE via the NVD CPE API, then `virtualMatchString` for version-accurate CVEs — keyword search can't do version matching), EPSS + KEV enrichment, a `vulns` store table, `pontus-cli scan --assess-vulns`, and `pontus-cli risk` (hosts ranked fix-first). Live-verified: OpenSSH 8.2p1 → 16 applicable CVEs, EPSS-enriched, top = CVE-2023-48795 (Terrapin). GUI risk view (`View ▸ Risk / vulnerabilities…`, Ctrl+R): a shared `store::risk_ranked` (the single scoring path for CLI + FFI + GUI) → FFI `pontus_risk_json` → a Qt master/detail dialog — hosts worst-first with risk score, vuln count and top finding; selecting a host lists its CVEs (band, CVSS, EPSS-as-%, KEV badge), band-coloured.
- **F-013 (done, core+CLI):** native OS fingerprinting in the `os` module (D-011) — a passive, **p0f-style family-level** guess (Linux/Unix, Windows, *BSD, macOS, Network/Embedded) from a `StackSignature` read off the SYN-ACK: the **TCP-option layout** (the order of MSS/SACK/Timestamp/NOP/Window-scale — the strongest discriminator: Linux `MSTNW`, Windows `MNWNNS`, macOS `MNWNNTSEE`), **initial TTL**, **window**, **DF bit**, plus **volunteered banner tokens** and the ICMP echo-reply TTL for portless hosts (IMP-006). Scored against an `OsCorpus` whose built-in defaults are clean-room (public IP-stack option orders/TTLs + host-emitted strings, never `nmap-os-db`, C-001) and which a `--os-corpus <path>` JSON file layers over at runtime (updatable without a rebuild). Confidence blends agreement × evidence-strength, so a lone TTL caps at 0.5 and a matching option layout lifts it to ~0.8 (BUG-006). Recorded in `os_guess`; CLI prints `os: <family> (<conf>% — evidence)`. IPv6 keeps the option layout + window but loses TTL/DF (kernel strips the v6 header, BUG-005). Live-verified on the /24: a known-Linux host → `opts=MSTNW` → "Linux/Unix (80% — initial TTL 64, TCP options MSTNW)". The work sits behind an `OsDetector` trait (like the service `Detector`): `NativeOsDetector` (passive default) + `NmapOsDetector` — an opt-in `--os-detector nmap` backend that shells out to the user's own `nmap -O` for a version-range guess (parses only Nmap's verdict, never `nmap-os-db`, C-001/D-006; needs sudo for `-O`'s raw sockets). ~21 `os` unit tests.
- **F-016 (done, core+CLI):** TLS/SSL inspection in the `tls` module (D-012) — a clean-room, **pure-Rust prober with no OpenSSL/crypto dependency**: it hand-rolls `ClientHello`s and parses `ServerHello`/`Certificate` directly (sslscan-style), so it sees what a normal client won't. Enumerates protocols **SSLv3–TLS 1.3** (1.3 via supported_versions/key_share), probes **weak-cipher acceptance** (offers a weak-only suite list at 1.2), and captures the cert from a TLS ≤1.2 `Certificate` message (in the clear), inspected via `x509-parser` (expiry, self-signed, weak signature SHA-1/MD5, RSA<2048, SAN/hostname incl. wildcard match). `pontus-cli tls <host> [--port N] [--scope …]` reports protocols/ciphers/cert/findings; scope-enforced (F-007), defaulting scope to the target. Live-verified against badssl.com: `expired.badssl.com` → "certificate has expired", `self-signed.badssl.com` → "self-signed", badssl.com → deprecated TLS 1.0/1.1 + 3DES accepted. Limitation: a TLS 1.3-only server encrypts its cert, so cert capture needs ≤1.2 (IMP-009). 7 `tls` unit tests on the wire codecs.
- **F-017 (done, core+CLI):** HTTP tech fingerprinting in the `webtech` module — Wappalyzer-style stack ID from response **headers** (`Server`, `X-Powered-By`, `Set-Cookie` names, CDN markers like `CF-Ray`/`X-Served-By`), the **`<meta generator>`** tag, and **body markers** (`/wp-content/`, `jquery-3.x.js`, `/_next/`), classified into server/language/framework/cms/js-library/cdn/analytics with versions where exposed. Clean-room signature set (not from Wappalyzer's dataset, C-001), reusing the existing `ureq` client (no new HTTP dep). `pontus-cli http <host> [--port N] [--scope …]`, scope-enforced. Live-verified: wordpress.org → nginx + WordPress 7.1; python.org → nginx + jQuery 1.8.2 + Fastly. 6 unit tests. **Phase 3 is complete** (F-012/F-013/F-014/F-015/F-016/F-017 all done).
- **GUI consolidation (done):** Phase-3 intelligence is now visible in the desktop app. OS guess (IMP-004) shows as an "OS" column in the inventory (latest `os_guess` via a `json_extract` subquery on `AssetSummary`) and in the observation history. TLS (IMP-008) and web-tech (IMP-010) are folded into scans: `scan --inspect` runs `tls::inspect` on open 443/8443 and `webtech::fingerprint` on open 80/443/8080/8000/8443, attaching a compact `TlsObservation`/`TechObservation` to each `PortObservation` in the observation `state` (JSON, no migration, flows through the existing FFI). The GUI asset detail has a "Deep inspection" panel for the latest observation's TLS findings + detected tech. Verified end-to-end locally (a `--inspect` scan of a local HTTP server records & shows `web: SimpleHTTP`).
- **Identity merge (BUG-012, done):** a host first seen by ARP then later by ICMP-only (a MAC-less sighting) used to fork a second, IP-anchored asset, so one physical host showed up twice in the inventory. The bare-IP fallback in `identity::resolve` now attaches a genuinely MAC-less sighting to whichever asset already lives at that address (most-recent-first, so a recycled lease follows its present tenant), regardless of anchor; a sighting carrying a new, unmatched MAC stays a distinct host (recycle guard). IP remains a locator, never an anchor (C-003 intact). **Prevention only** — append-only observations (D-007) mean pre-existing duplicates can't be merged retroactively; they go stale once the fix routes new sightings to the canonical asset. Three tests in `asset_store.rs`.

### Phase 4 progress

- **F-018 (done, core):** `pontus-daemon` — unattended scheduled rescans. A new `pontus-daemon` crate reads a TOML config of jobs (`config.rs`: targets/scope/interval + the scan options that map to `pontus-cli scan` flags; human-duration parser `30s`/`15m`/`6h`/`1d`, validated at load) and runs one tokio timer per job (`scheduler.rs`). Each run shells out to the capability-granted CLI (D-008) — the daemon holds no raw privilege and never touches the store directly, so scan orchestration stays in one place; results land as ordinary append-only observations against the resolved assets (D-007), feeding drift/baseline/risk with no extra wiring. Scans serialise through a shared single-writer lock (one SQLite writer at a time); `run_at_start` (default true) produces a baseline immediately; `--once` runs each job a single time (config check / cron). `make daemon [DCONFIG=…]` (depends on `cap`) and `examples/pontus-daemon.toml`. 8 unit tests (arg construction, duration parsing, config validation); live-verified end-to-end (a daemon-driven loopback scan wrote a durable asset + observation).
- **F-019 (done, email channel pending):** alert rules + delivery. Headless matching in `pontus-core` `alert` module (`Condition`/`Rule`/`Alert`/`evaluate`) over the scan diff — conditions `port_opened`/`port_closed`/`host_new`/`host_vanished`/`host_changed`/`address_moved` with optional port/proto filters. The daemon, after each scheduled scan, opens the store read-only, diffs this job's latest scan against its previous one (matched by target range, so interleaved jobs don't cross-contaminate) and delivers matches (`scheduler::evaluate_drift` + `alerts::deliver`). "Exactly once" falls out of diffing consecutive scans (a change appears once); the first scan of a range has no baseline so never alerts. Channels: `log`, `desktop` (notify-send), generic `webhook`, `slack`/`discord` (their webhook JSON shapes) — `ureq` POST with a 10s timeout, failures logged not fatal; the read+diff+deliver runs on a blocking thread off the async runtime. `[[alert]]` rules + `[channels.*]` URLs, validated at startup (unknown/unconfigured channel rejected). The daemon now links `pontus-core` read-only for this (privileged scanning still shells out, D-008). 6 core + 5 daemon tests (incl. a real two-scan store drift test); live-verified end-to-end (a newly-opened loopback port fired exactly one alert over a webhook; baseline/unchanged scans fired none). **Email/SMTP is the one remaining channel** (a dependency decision, deferred).
- **F-020 (in progress — Lua runner done):** the `pontus-plugins` crate (D-003). The stable, serde-driven contract lives in `finding.rs` (`Finding`/`Severity`/`Target`/`TargetPort` — every type serialisable so the same shape crosses any runner's boundary) and `plugin.rs` (`Plugin`/`Language`/`PluginSource`, the `PluginRunner` trait, and `PluginHost` which routes a plugin to the runner for its language and stamps `Finding::plugin`). The **Lua runner** (`lua.rs`, mlua 0.10 vendored + serialize): a plugin defines a global `check(target)` returning finding tables, which `LuaSerdeExt::to_value`/`from_value` marshal with no hand-written glue. The Lua state uses a curated, filesystem-free stdlib (base + table/string/math/coroutine; **no io/os/package/debug**) plus a memory limit — "lightweight built-ins" per D-003; a CPU/instruction limit is a planned follow-up and the fully-untrusted path is the WASM runner (wasmtime fuel). Example `plugins/telnet.lua`. 11 tests incl. sandbox proofs (io/os absent) and on-disk plugin load. **Chosen slicing (user): Lua first, then WASM, then Python.**
- **F-020 WASM runner (done):** the untrusted tier in `wasm.rs` (wasmtime). Run with **no host imports at all**, so a module structurally cannot reach the filesystem/network — a module that even imports a WASI call fails to instantiate. Fuel metering traps runaway loops; a `StoreLimits` memory cap bounds growth. ABI: the guest exports `memory` + `run(target_ptr, target_len) -> i64` returning a packed `(result_ptr << 32) | result_len` for a findings JSON array, and optionally `alloc(len) -> ptr` so the host can place the target JSON in guest memory; `.wasm` binaries and `.wat` text both load. Tests use hand-written WAT (no wasm toolchain needed): runs a plugin, WASI-import rejection, fuel-trapped infinite loop, zero-return, missing-memory. 5 wasm tests (16 crate total).
- **F-020 Python runner (done):** the trusted, full-power tier in `python.rs` (pyo3 0.23, abi3-py38 + auto-initialize). Deliberately **not** sandboxed (D-003: Python = trusted) — a plugin defines `check(target)` taking a dict and returning finding dicts, with JSON as the interchange (`json.loads`/`json.dumps`, symmetric with the WASM runner, no Pontus-specific bindings). **Opt-in behind the `python` Cargo feature** (`python = ["dep:pyo3"]`, off by default) so default builds need no libpython; `cargo build/test -p pontus-plugins --features python`. Example `plugins/telnet.py`. 6 tests (run with the feature). Runtime note: the test/binary needs libpython on the loader path — `LD_LIBRARY_PATH=$(python3 -c 'import sysconfig;print(sysconfig.get_config_var("LIBDIR"))')` (e.g. conda's `lib`); see BUILD.md.
- **F-020 scan wiring (done):** plugins run during scans. `pontus-cli scan --plugins <dir>` loads plugins by extension (`.lua`/`.wasm`/`.wat`/`.py`; `.py` needs a `--features python` build, otherwise skipped with a note), builds a `pontus_plugins::Target` from each up host's observed ports/services, runs every loaded plugin via the `PluginHost`, and persists findings to a new `findings` store table (`record_finding`/`findings_for_scan`, `StoredFinding`; the store stays independent of the plugin runtime — the CLI maps `Finding` → row). `pontus-cli findings [--scan]` lists them. The CLI's own `python` feature forwards to `pontus-plugins/python`. Live-verified: a Lua plugin saw a scanned host's open port and recorded findings read back by the `findings` command. **F-020 is complete** (all three runners + API + scan wiring).
- **Next:** F-021 (first-party plugins — SMB enum, SNMP walk, SSH host-key, HTTP header audit — plus a guest SDK so a real cross-compiled WASM plugin demonstrates full target-aware parity), then F-022 (credentialed scanning). Smaller open items: a GUI findings view (surface `findings_for_scan` in the desktop app); IMP-009 (TLS 1.3-only cert capture); F-019 email channel.

## Active task

Phase 2, GUI skeleton — in progress. The Qt shell (inventory + detail) and GUI-driven scanning are in; next deliverables are the topology graph (F-009), heatmap (F-011), the in-GUI diff view (F-014), and saveable profiles (F-010). The core is feature-complete for Phase 1; new work is GUI-side over the `pontus-ffi` read surface plus CLI shell-out for scans.

**Phase 1 acceptance (status):**

- Workspace builds; `pontus-core` and `pontus-cli` are present. ✅
- A CLI scan of a reference /24 writes one asset per host and an observation set. ✅ (live)
- A forced IP change resolves to the same asset (F-004 acceptance). ✅ (unit; stable across live re-scan)
- An out-of-scope target is refused before any packet is sent (F-007). ✅
- Hybrid port scan results match a full Nmap SYN scan on a reference host. ✅ (live, exact match)

## Architectural invariants

Full rationale in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); the load-bearing rules:

- The core is headless — CLI and GUI are both clients of `pontus-core` (D-001).
- Observations are append-only; a scan never mutates prior observations (D-007).
- Host identity resolves MAC → host key/cert → hostname → IP; IP is never the primary key (C-003, F-004).
- Scope enforcement is unconditional and cannot be disabled by config (F-007).
- No bundled or required Nmap; the Nmap-backed detector shells out to a user binary (D-006, C-001).
- IPv6 parity from Phase 1 (D-004).
- Untrusted/WASM plugins run sandboxed with no ambient FS/network authority (D-003).

## Build & test commands

A root `Makefile` wraps the build/setcap/run loop (`make help` for the list):

```bash
make build        # cargo build --release + build the Qt GUI (gui/build)
make cap          # build + setcap cap_net_raw+ep on the release CLI (sudo only if missing)
make test         # cargo test
make gui          # build + cap + run the GUI (GUI scans get raw privilege)
make scan T=192.168.1.0/24 P=22,80,443 U=53,161,5353   # scope defaults to T
```

Or directly:

```bash
cargo build --release && cargo test
sudo setcap cap_net_raw+ep target/release/pontus-cli
./target/release/pontus-cli scan 192.168.1.0/24 --scope 192.168.1.0/24
cmake -S gui -B gui/build && cmake --build gui/build   # Qt GUI (needs Qt6 + CMake)
```

Raw-socket scanning requires `CAP_NET_RAW` (or root); prefer granting the capability over running as root. The capability lives on the binary file, so a rebuild drops it — but `make cap`/`make gui`/`make scan` all depend on `cap`, which re-applies it (one sudo prompt) **only when actually missing**, so the documented `make` workflow self-heals after a rebuild. (A raw `cargo build` + direct run still needs a manual `setcap`.)

## Conventions

- **Documentation standard:** project-scaffold (github.com/Darian-Frey/project-scaffold). British English throughout. ISO 8601 dates. README status blockquote header (Status / Provenance / Last reviewed / Why this status).
- **Register placement (note the divergence from the scaffold's file-per-register default):** this project uses the five-document set (README, VISION, ARCHITECTURE, ROADMAP, CLAUDE), so `C-NNN` and `F-NNN` live in VISION.md and `D-NNN` lives in ARCHITECTURE.md. If the registers grow unwieldy, split `FEATURES.md` and `DECISIONS.md` out as their own Tier 1/2 files per the standard — that is a `D-NNN` decision when it happens.
- **Append-only IDs:** F-NNN, C-NNN, D-NNN, BUG-NNN, IMP-NNN, (AV-NNN reserved). Never deleted or renumbered; withdrawn/superseded entries get a status flag. `BUG-NNN` lives in docs/BUGS.md and `IMP-NNN` in docs/IMPROVEMENTS.md (adopted in D-010); both follow the "log when found, not silently acted on" discipline.
- **Every decision needs a reversal condition** — without one it's a belief, not a decision.
- **Naming:** Greek/Latin primordial mythology for project names (Pontus = the primordial sea; charting the unknown sea of hosts). Rust crates use the `pontus-*` prefix.
- **Commit messages:** imperative mood; reference D-NNN / F-NNN in the body when applicable.
- **Status/Why fields** on any repo are proposed for Shane's confirmation, never committed silently.

## Pitfalls

- **The asset model is the core, not the scanner (D-007).** Resist any design that makes a scan primary and inventory a by-product — it quietly breaks drift/baseline/time-travel. If a change feels like it needs a retrospective join across scans to diff, the model is being subverted.
- **Licensing trap (C-001).** Do not vendor `nmap-service-probes` / `nmap-os-db`, copy their entries, or derive the native corpus from them. The native detector must be clean-room; Nmap coverage comes only via runtime shell-out.
- **Scope enforcement is a safety feature, not a setting.** Do not add a flag to disable it. This is a network tool that can disrupt what it scans.
- **Don't over-engineer the store.** D-007 chose two relational tables deliberately, not event-sourcing. Reach for the lightweight shape first.

## Out of scope

The AI partner should not change these without asking:

- The three-tier split or the headless-core invariant (D-001) — these are `D-NNN` decisions.
- The asset-centric data model (D-007) and the identity-resolution hierarchy (C-003).
- The no-bundled-Nmap posture (D-006, C-001).
- The licence choice (currently undecided; candidate dual MIT/Apache-2.0).
- The non-goals in VISION.md (no exploitation framework, no credential cracking, no packet-capture/IDS scope).
