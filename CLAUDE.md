# CLAUDE.md

## Project

Pontus is a GUI-native network scanner and asset-inventory platform — a modern, stateful successor to Nmap/Zenmap. Phase 1 is under way: the document set is complete and the native Rust core + CLI now build and run.

## Current state

- `docs/VISION.md`: complete. Problem, differentiation, design principles, non-goals, `C-NNN` claims register (C-001–C-005), `F-NNN` feature register (F-001–F-035; F-029–F-035 are the GUI interface features).
- `docs/ARCHITECTURE.md`: complete. Three-tier design, hybrid scan pipeline, asset/observation data model, invariants, `D-NNN` decision register (D-001–D-007; D-005 superseded by D-006).
- `docs/ROADMAP.md`: complete. Five phases mapping to the feature register.
- `README.md`: complete. Status header, intended quick-start/structure, documentation map.
- `crates/pontus-core`, `crates/pontus-cli`, `crates/pontus-ffi`: exist and build (Cargo workspace). `gui/`: Qt6 shell exists and builds (CMake, links `pontus-ffi`). `plugins/` and the other crates do not exist yet.
- No `CHANGELOG.md`, `BUILD.md`, `DECISIONS.md`, `FEATURES.md` as separate files yet — see "Conventions" for where those registers currently live.

### Phase 1 progress

- **Done:** workspace scaffold; `pontus-core` `assets`/`observations`/`scans` schema with trigger-enforced append-only observations (F-003); identity resolution MAC → host-key → hostname → IP with promotion (F-004); unconditional scope enforcement + audit log (F-007); native host discovery — ARP + ICMP echo over IPv4/IPv6 with privilege fallback (F-001); hybrid scan pipeline — stateless SYN sweep → stateful connect/banner deep pass, shared raw-socket plumbing in `raw.rs` (F-002); scan diff — headless `diff::diff_observations` comparing two scans by `asset_id` (F-014 first cut); `pontus-cli` scan/assets/diff (F-005). Validated live on a reference /24: 7 hosts → 7 durable assets, stable across three re-scans; port scan of a reference host is an exact match with `nmap -sS`; drift surfaces opened/closed ports against a stable asset.
- **Refinements (all done):** rDNS fills the hostname tier (`rdns::reverse_lookup`, `--no-rdns`); UDP scanning via connected sockets (`scan::udp`, open/closed/open|filtered, `--udp-ports`) with clean-room protocol payloads (`scan::udp_probes`: DNS/NTP/SNMP/SSDP/mDNS, C-001); diff is proto-aware (`PortRef`, so `tcp/53` ≠ `udp/53`); the stateless sweep is batched for wide ranges (`raw::BatchSender`, per-/24 source cache). Validated live: router DNS/NTP/UPnP and host mDNS confirmed open with data.

### Phase 2 progress

- **Done:** `pontus-ffi` C-ABI shim (`pontus_open`/`assets_json`/`scans_json`/`asset_history_json`/`diff_json`/`string_free`; opaque handle; JSON across the boundary; hand-written `include/pontus.h`) — read surface only, D-001. `gui/` Qt6 Widgets shell (CMake, links `libpontus_ffi`): filterable asset table + per-asset observation-history detail pane (F-008), and a New-scan dialog with mandatory scope + live output that shells out to the privileged `pontus-cli` (D-008, F-010 first cut). Verified live on a reference /24.
- **Next:** still open in Phase 2 — live topology graph (F-009), service/port heatmap (F-011), saveable scan profiles (F-010), and the drift/diff view in the GUI (renders `pontus_diff_json`, F-014). The FFI write surface is deliberately avoided so far (scan-from-GUI uses the CLI shell-out, D-008).

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

```bash
# Not yet implemented — target commands for Phase 1
cargo build --release
cargo test
sudo ./target/release/pontus-cli scan 192.168.1.0/24 --scope 192.168.1.0/24
```

Raw-socket scanning requires `CAP_NET_RAW` (or root); prefer granting the capability over running as root.

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
