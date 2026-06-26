# CLAUDE.md

## Project

Pontus is a GUI-native network scanner and asset-inventory platform — a modern, stateful successor to Nmap/Zenmap. Phase 1 is under way: the document set is complete and the native Rust core + CLI now build and run.

## Current state

- `docs/VISION.md`: complete. Problem, differentiation, design principles, non-goals, `C-NNN` claims register (C-001–C-005), `F-NNN` feature register (F-001–F-035; F-029–F-035 are the GUI interface features).
- `docs/ARCHITECTURE.md`: complete. Three-tier design, hybrid scan pipeline, asset/observation data model, invariants, `D-NNN` decision register (D-001–D-007; D-005 superseded by D-006).
- `docs/ROADMAP.md`: complete. Five phases mapping to the feature register.
- `README.md`: complete. Status header, intended quick-start/structure, documentation map.
- `crates/pontus-core`, `crates/pontus-cli`, `crates/pontus-ffi`: exist and build (Cargo workspace). `gui/`: Qt6 shell exists and builds (CMake, links `pontus-ffi`). `plugins/` and the other crates do not exist yet.
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
- **F-015 (done, core+CLI):** NVD CVE matching by **CPE applicability** (resolve product→CPE via the NVD CPE API, then `virtualMatchString` for version-accurate CVEs — keyword search can't do version matching), EPSS + KEV enrichment, a `vulns` store table, `pontus-cli scan --assess-vulns`, and `pontus-cli risk` (hosts ranked fix-first). Live-verified: OpenSSH 8.2p1 → 16 applicable CVEs, EPSS-enriched, top = CVE-2023-48795 (Terrapin). GUI risk view (FFI `risk_json` + a Qt view) still to add.
- **Next:** the GUI risk view, then OS fingerprinting (F-013) and TLS/HTTP inspection (F-016/F-017).

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
make cap          # sudo setcap cap_net_raw+ep on the release CLI (re-run after each build)
make test         # cargo test
make gui          # run the GUI, using the release CLI for scans
make scan T=192.168.1.0/24 P=22,80,443 U=53,161,5353   # scope defaults to T
```

Or directly:

```bash
cargo build --release && cargo test
sudo setcap cap_net_raw+ep target/release/pontus-cli
./target/release/pontus-cli scan 192.168.1.0/24 --scope 192.168.1.0/24
cmake -S gui -B gui/build && cmake --build gui/build   # Qt GUI (needs Qt6 + CMake)
```

Raw-socket scanning requires `CAP_NET_RAW` (or root); prefer granting the capability over running as root. Capabilities are dropped on every rebuild, so re-run `make cap` (or the `setcap` line) after building.

## Conventions

- **Documentation standard:** project-scaffold (github.com/Darian-Frey/project-scaffold). British English throughout. ISO 8601 dates. README status blockquote header (Status / Provenance / Last reviewed / Why this status).
- **Register placement (note the divergence from the scaffold's file-per-register default):** this project uses the five-document set (README, VISION, ARCHITECTURE, ROADMAP, CLAUDE), so `C-NNN` and `F-NNN` live in VISION.md and `D-NNN` lives in ARCHITECTURE.md. If the registers grow unwieldy, split `FEATURES.md` and `DECISIONS.md` out as their own Tier 1/2 files per the standard — that is a `D-NNN` decision when it happens.
- **Append-only IDs:** F-NNN, C-NNN, D-NNN, (AV-NNN reserved). Never deleted or renumbered; withdrawn/superseded entries get a status flag.
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
