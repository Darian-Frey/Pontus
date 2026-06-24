# Pontus — dev convenience targets.
#
# Wraps the build / setcap / run loop so paths and capabilities don't have to be
# retyped. Everything here drives the Cargo workspace and the Qt GUI; it adds no
# behaviour to the app itself. Run `make` (or `make help`) for the list.

ROOT := $(shell pwd)
CLI  := target/release/pontus-cli
GUI  := gui/build/pontus-gui
DB   ?= pontus.db

.PHONY: help build build-debug test clippy cap gui scan clean

help:
	@echo "Pontus dev targets:"
	@echo "  make build        cargo build --release + build the Qt GUI"
	@echo "  make build-debug  cargo build (debug) — fast iteration on the core/CLI"
	@echo "  make test         cargo test"
	@echo "  make clippy       cargo clippy --all-targets"
	@echo "  make cap          grant CAP_NET_RAW to the release CLI (sudo; re-run after each build)"
	@echo "  make gui          run the GUI, using the release CLI for scans (DB=$(DB))"
	@echo "  make scan T=192.168.1.0/24 [S=<scope>] [P=22,80,443] [U=53,161,5353] [DB=<db>]"
	@echo "  make clean        remove build artefacts"

build:
	cargo build --release
	cmake -S gui -B gui/build -DPONTUS_TARGET_DIR=$(ROOT)/target/release
	cmake --build gui/build

build-debug:
	cargo build

test:
	cargo test

clippy:
	cargo clippy --all-targets

# Raw-socket scanning needs CAP_NET_RAW. Capabilities are attached to the binary
# file, so they are dropped on every rebuild — re-run this after `make build`.
cap:
	sudo setcap cap_net_raw+ep $(CLI)

# Launch the GUI with PONTUS_CLI pointed at the (privileged) release CLI, so scans
# started from the GUI use it rather than falling back to an unprivileged probe.
gui:
	PONTUS_CLI=$(ROOT)/$(CLI) $(GUI) $(DB)

# Privileged CLI scan. Scope defaults to the target range when S is omitted.
scan:
	@test -n "$(T)" || { echo "usage: make scan T=<targets> [S=<scope>] [P=<tcp-ports>] [U=<udp-ports>] [DB=<db>]"; exit 2; }
	$(CLI) scan $(T) --scope $(or $(S),$(T)) --db $(DB) $(if $(P),--ports $(P)) $(if $(U),--udp-ports $(U))

clean:
	cargo clean
	rm -rf gui/build
