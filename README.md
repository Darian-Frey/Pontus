> **Status:** Active
> **Provenance:** Shane Hartley (architect); Claude (document generation, primary auditor) — concept and document set, 2026-06-22
> **Last reviewed:** 2026-06-22
> **Why this status:** Concept and architecture settled; no code written yet. Phase 1 (native engine + asset store) is the next work item.

# Pontus

Pontus is a modern, GUI-native network scanner and asset-inventory platform — what Nmap would be if it were built today around a persistent asset model rather than point-in-time output. It owns its packet engine (Rust, async, raw sockets), treats every host as a durable entity tracked across scans, and layers actionable vulnerability intelligence (EPSS + CISA KEV, not just raw CVE dumps) on top. It is for network operators, security engineers and home-lab owners who need to know not just *what is on the network now* but *what changed* — with Zenmap effectively unmaintained, the GUI-native niche is open.

## Quick Start

> Not yet implemented — this is the target Phase 1 workflow, recorded so the scaffolding has a destination.

```bash
git clone https://github.com/Darian-Frey/pontus
cd pontus
cargo build --release

# Raw-socket scanning needs CAP_NET_RAW (or root). Scope is mandatory —
# Pontus refuses to send packets outside the authorised range (F-007).
sudo ./target/release/pontus-cli scan 192.168.1.0/24 --scope 192.168.1.0/24
```

## Build requirements

- Rust (stable, 1.85+) and Cargo for `pontus-core`, `pontus-cli`, and the FFI shim
- Qt 6.5+ and a C++20 toolchain for the desktop GUI (Phase 2 onward)
- Linux first (raw sockets via `CAP_NET_RAW`); Windows is a Phase 5 target
- SQLite (bundled via `rusqlite`) — no external database server

See [BUILD.md](BUILD.md) for detailed setup (planned; added when Phase 1 lands).

## Project structure

```
pontus/
├── crates/
│   ├── pontus-core/      Rust scan engine, Detector trait, asset/observation model
│   ├── pontus-ffi/       C-ABI shim exposing pontus-core to the Qt GUI (D-001)
│   ├── pontus-cli/       Command-line front-end over pontus-core
│   ├── pontus-daemon/    Scheduled-rescan + alerting service (Phase 4)
│   └── pontus-plugins/   Plugin host: pyo3 / mlua / wasmtime (Phase 4, D-003)
├── gui/                  Qt6 / C++20 desktop frontend (Phase 2)
├── plugins/             First-party plugin sources
├── docs/                VISION, ARCHITECTURE, ROADMAP
└── Cargo.toml           Workspace manifest
```

## Documentation

- [Vision](docs/VISION.md) — the problem, the Nmap gap, differentiation, design principles, feature register (F-NNN) and load-bearing claims (C-NNN)
- [Architecture](docs/ARCHITECTURE.md) — three-tier structure, the asset/observation data model, invariants, and the decision register (D-NNN)
- [Roadmap](docs/ROADMAP.md) — five-phase plan, features mapped to phases
- [CLAUDE.md](CLAUDE.md) — handoff for AI-assisted sessions

## License

Undecided — candidate is dual **MIT / Apache-2.0** (the Rust-ecosystem standard). The choice is constrained by C-001 (Nmap's fingerprint data ships under the restrictive NPSL); Pontus stays clear of that entanglement by design (D-006), which keeps a permissive licence open. To be fixed before first public tag.
