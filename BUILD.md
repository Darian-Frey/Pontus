> **Status:** Active
> **Provenance:** Shane Hartley (architect); Claude (document generation) — 2026-06-25
> **Last reviewed:** 2026-06-25
> **Why this status:** Phases 1 and 2 build and run; this reflects the current Rust + Qt toolchain. Windows is a Phase 5 target and not covered yet.

# Building Pontus

Pontus is a Rust workspace (`pontus-core`, `pontus-cli`, `pontus-ffi`) plus a
Qt6/C++20 desktop GUI (`gui/`) that links the core through the `pontus-ffi`
C-ABI shim (D-001). Linux is the first-class platform.

## Requirements

| Component | Version | Notes |
|-----------|---------|-------|
| Rust + Cargo | 1.85+ (stable) | The `2024` edition. Developed against 1.95. |
| C++ toolchain | C++20 | g++ 13+ or clang 16+. |
| CMake | 3.16+ | Drives the GUI build. |
| Qt 6 | 6.5+ recommended | Builds against 6.4 in practice (Widgets only). Needs the `Widgets` component. |
| SQLite | — | Bundled via `rusqlite` (`bundled` feature); no system SQLite needed. |

No `libpcap` or external scan engine is required — the packet engine is native
(`pnet`/`socket2`) and there is no bundled or required Nmap (D-006, C-001).

On Debian/Ubuntu, the GUI prerequisites are roughly:

```bash
sudo apt install build-essential cmake qt6-base-dev
```

## Quick build (Makefile)

A root `Makefile` wraps the whole loop; `make help` lists every target.

```bash
make build      # cargo build --release + configure/build the Qt GUI
make cap        # sudo setcap cap_net_raw+ep on the release CLI (see "Capabilities")
make test       # cargo test
make gui        # run the GUI (scans use the privileged release CLI)
make scan T=192.168.1.0/24 P=22,80,443 U=53,161,5353   # a privileged CLI scan
```

## Manual build

```bash
# 1. The Rust workspace (produces target/<profile>/{pontus-cli, libpontus_ffi.so})
cargo build --release
cargo test

# 2. The Qt GUI — point CMake at the matching Cargo target dir
cmake -S gui -B gui/build -DPONTUS_TARGET_DIR=$(pwd)/target/release
cmake --build gui/build
# → gui/build/pontus-gui
```

For a debug GUI build, omit `-DPONTUS_TARGET_DIR` (it defaults to `target/debug`)
and `cargo build` (debug) instead.

## Optional Python plugin runner (`python` feature)

The plugin host (`pontus-plugins`) ships three runners (F-020, D-003). The Lua and
WASM runners are always built and need nothing extra. The **Python** runner (pyo3)
is **opt-in**, because it links `libpython`: building it needs Python dev headers
and running its plugins needs an interpreter present.

```bash
# Build/test only the Lua + WASM runners (default — no Python needed):
cargo test -p pontus-plugins

# Enable the Python runner too:
cargo test -p pontus-plugins --features python
```

pyo3 builds against the Python found on `PATH` (override with `PYO3_PYTHON`). With
a non-system interpreter (e.g. conda) the resulting binary may not find
`libpython` at run time; put its lib dir on the loader path:

```bash
export LD_LIBRARY_PATH="$(python3 -c 'import sysconfig; print(sysconfig.get_config_var("LIBDIR"))'):$LD_LIBRARY_PATH"
```

## Capabilities (raw sockets)

Raw-socket discovery, the SYN sweep and traceroute need `CAP_NET_RAW`. Grant it to
the CLI rather than running as root:

```bash
sudo setcap cap_net_raw+ep target/release/pontus-cli
```

Without the capability the CLI still runs, degrading to an unprivileged
TCP-connect discovery/scan and skipping traceroute (you'll see a `note:` to that
effect). Scope enforcement (F-007) is unconditional either way.

## Running

```bash
# CLI — scope is mandatory; nothing is scanned outside it
./target/release/pontus-cli scan 192.168.1.0/24 --scope 192.168.1.0/24
./target/release/pontus-cli assets
./target/release/pontus-cli diff

# GUI — opens an existing store; scans launched from it use the privileged CLI
gui/build/pontus-gui pontus.db
```

The GUI finds a `pontus-cli` to drive scans via, in order: the `PONTUS_CLI`
environment variable, then alongside the GUI binary, then the dev `target/`
directories, then `PATH`. To force a specific (capability-granted) CLI:

```bash
PONTUS_CLI=$(pwd)/target/release/pontus-cli gui/build/pontus-gui
```

## Troubleshooting

- **A scan finds nothing / no MAC addresses / no topology edges, and prints a
  `CAP_NET_RAW` note.** The CLI lacks the capability — re-run `make cap` (or the
  `setcap` line). **Capabilities are attached to the binary file and are dropped
  on every rebuild**, so re-apply after each `cargo build`/`make build`.

- **`undefined symbol: pontus_*` when launching the GUI.** The GUI loaded a stale
  `libpontus_ffi.so`. Its `RUNPATH` lists `target/release` before `target/debug`,
  so after changing the FFI you must rebuild the profile it actually loads —
  simplest is `cargo build --release` (what `make build` does). Confirm with
  `nm -D target/release/libpontus_ffi.so | grep pontus_`.

- **`make build` fails with "No rule to make target".** You're on a branch/commit
  without the `Makefile`; use the manual `cargo`/`cmake` commands above.

- **CMake can't find `libpontus_ffi`.** Build the Rust workspace first, and pass
  `-DPONTUS_TARGET_DIR=<dir>` matching the profile you built (`target/release`
  or `target/debug`).

- **Qt not found by CMake.** Ensure the Qt6 `Widgets` dev package is installed and
  on CMake's prefix path (e.g. `qt6-base-dev` on Debian/Ubuntu).

## Platform notes

Linux is the development and reference platform. Windows is a Phase 5 target
(F-028) and is not yet supported; the raw-socket and capability model there will
differ (Administrator/Npcap rather than `CAP_NET_RAW`).
