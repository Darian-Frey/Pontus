# pontus-gui

The Qt6 desktop frontend (Phase 2, F-008). Its home screen is the asset
inventory: a filterable table of durable assets with a detail pane showing the
selected asset's observation history. It is a client of `pontus-core` through the
`pontus-ffi` C-ABI shim (D-001) — it does not scan; it displays a store the CLI
(or, later, a scan launched from the GUI) populated.

## Requirements

- Qt 6 (Widgets) and a C++20 compiler
- CMake 3.16+
- The Cargo workspace built first, so `libpontus_ffi` exists

## Build

```bash
# from the workspace root: build the FFI shared library
cargo build

# then the GUI
cmake -S gui -B gui/build
cmake --build gui/build
```

For a release build, point CMake at the release artefacts:

```bash
cargo build --release
cmake -S gui -B gui/build -DPONTUS_TARGET_DIR=$(pwd)/target/release
cmake --build gui/build
```

The executable embeds an RPATH to the Cargo target directory, so it finds
`libpontus_ffi.so` at runtime without `LD_LIBRARY_PATH`.

## Run

```bash
# open a database the CLI produced
gui/build/pontus-gui path/to/pontus.db

# or launch and open via File ▸ Open database…
gui/build/pontus-gui
```

### Headless self-test

A display-free smoke check of the FFI/JSON path (used in CI/sandboxes):

```bash
gui/build/pontus-gui --selftest path/to/pontus.db
# -> pontus-gui selftest ok: version=… assets=N
```
