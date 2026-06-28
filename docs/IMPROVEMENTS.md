> **Status:** Active
> **Provenance:** Shane Hartley (architect); Claude (improvement logging) — 2026-06-26
> **Last reviewed:** 2026-06-26
> **Why this status:** In-repo improvement catalogue adopted alongside BUGS.md mid-Phase 3 (adopting decision D-010 in ARCHITECTURE.md). Seeded from the F-015 work; maintained continuously per Maintenance Rule 8 ("log when noticed, not silently applied").

# Improvements

Catalogue of code-quality improvements, refactors, and architectural changes
proposed during development. Per the project workflow, improvements are **logged
here when noticed, not silently applied** — the author (Shane) decides whether to
apply, defer, or decline.

This is the dual of [BUGS.md](BUGS.md): bugs are things that are broken;
improvements are things that work but could be better (clarity, reuse,
maintainability, performance, future flexibility). An IMP entry is distinct from
a candidate feature (a user-facing capability, `F-NNN` in VISION.md) and from a
decision between alternatives (`D-NNN` in ARCHITECTURE.md): the question is "is
this internal change worth doing at all?"

`IMP-NNN` IDs are append-only and never renumbered. **Trade-offs are not
optional** — an entry without them is a wish-list item, not an improvement
candidate.

- **Status vocabulary:** suggested | applied | declined | deferred.
- **Effort vocabulary:** trivial | small | medium | large.

## Suggested

### IMP-005: Use the TCP window (and consider an active probe) to refine OS family

- **Status:** suggested
- **Found:** 2026-06-26, implementing F-013.
- **Location:** [crates/pontus-core/src/os.rs](../crates/pontus-core/src/os.rs).
- **Effort:** medium
- **Description.** The SYN-ACK's advertised TCP window is captured (`HostPorts::tcp_window`) and supported by the corpus schema, but the built-in corpus carries no window rules — so within a TTL family (e.g. the many OSes that start at 64) the guess can't discriminate further. Common default window sizes are publicly documented and could refine the family.
- **Proposal.** Add a small set of clean-room window rules to the built-in corpus (documented public defaults, not from `nmap-os-db`); longer term, a clean-room active probe sequence (D-011 option A) for version-level precision.
- **Trade-offs.** Window defaults overlap across OSes and are easily changed by middleboxes/tuning, so low-weight rules risk false precision; must stay advisory. An active probe sequence is a much larger build and closer to the C-001 line — gated behind real user demand per D-011's reversal condition.
- **Notes.** Builds on D-011. Independent of [IMP-004](#imp-004-surface-the-os-guess-in-the-gui-inventory).

### IMP-007: Richer p0f-style stack features (MSS, window-scale, quirks) and corpus tuning

- **Status:** suggested
- **Found:** 2026-06-26, implementing the TCP-option-layout stack signature for F-013.
- **Location:** [crates/pontus-core/src/scan/tcp.rs](../crates/pontus-core/src/scan/tcp.rs) (`option_layout`/`StackSignature`), [crates/pontus-core/src/os.rs](../crates/pontus-core/src/os.rs).
- **Effort:** medium
- **Description.** The stack signature captures the option *layout*, TTL, window and DF — but not the option *values* (MSS, window-scale factor) or p0f's "quirks" (e.g. non-zero ACK on a SYN, unusual flag/option combinations). These add discrimination, especially between Linux distributions/versions and BSD variants, and would let confidence climb higher when several features corroborate. The built-in option-layout rules also cover only the common Linux/Windows/macOS cases and will need tuning as stacks evolve.
- **Proposal.** Extend `StackSignature`/`OsSignals`/`OsRule` with `mss`, `window_scale` and a small set of quirk flags; parse them in `option_layout` (already iterating the options) and the IP/TCP headers; grow the built-in corpus and document the signature format for community contributions. Consider shipping a larger default corpus file under `examples/` rather than only inline rules.
- **Trade-offs.** More fields widen the data model and the corpus schema; MSS and window-scale values are influenced by path MTU and tuning, so they must be low-weight/advisory to avoid false precision. Diminishing returns versus the option layout, which already does most of the discrimination.
- **Notes.** Extends D-011 and the option-layout work. The active-probe path (D-011 option A) remains the route to version-level precision if family-level proves insufficient.

### IMP-009: Capture certificates from TLS 1.3-only servers

- **Status:** suggested
- **Found:** 2026-06-27, implementing F-016.
- **Location:** [crates/pontus-core/src/tls.rs](../crates/pontus-core/src/tls.rs).
- **Effort:** large
- **Description.** Certificate capture parses the `Certificate` message from a TLS ≤1.2 handshake, where it is in the clear. A TLS 1.3-only server encrypts its certificate (after `ServerHello`), so we cannot read it without performing the key exchange — such servers yield protocols/findings but no cert details.
- **Proposal.** Either complete a real TLS 1.3 handshake far enough to decrypt the `EncryptedExtensions`/`Certificate` (needs X25519 + HKDF + AEAD), or adopt `rustls` for cert capture per D-012's reversal condition while keeping the hand-rolled prober for legacy enumeration.
- **Trade-offs.** A real 1.3 handshake pulls in cryptography (the dependency D-012 deliberately avoided); rustls is the pragmatic route but adds a crypto provider (ring/aws-lc-rs). Worth it only if TLS 1.3-only endpoints without ≤1.2 become common in practice.
- **Notes.** Documented limitation of D-012. Independent of [IMP-008](#imp-008-integrate-tls-inspection-into-the-scan--observation-model).

## Applied

### IMP-011: Updatable web-tech signature file

- **Status:** applied (2026-06-28)
- **Found:** 2026-06-27, splitting the unfinished half of IMP-010.
- **Location:** [crates/pontus-core/src/webtech.rs](../crates/pontus-core/src/webtech.rs) (`WebCorpus`), [crates/pontus-cli/src/main.rs](../crates/pontus-cli/src/main.rs).
- **Effort:** medium
- **Description.** The web-tech signatures were compiled-in, unlike the OS corpus a `--os-corpus` file extends without a rebuild.
- **Proposal.** Lift the header/cookie/body/script signatures into a `WebCorpus` (mirroring `OsCorpus`: `builtin`/`from_json`/`extend`/`load`), keyed by a serde-friendly `Category`; add a `--web-corpus <path>` flag to `pontus-cli http` and `scan --inspect` that layers a user JSON file over the built-in defaults. `Server`/`<meta generator>`/`X-Powered-By` version parsing stays in code; the lists are the extensible data.
- **Trade-offs.** A schema to maintain, and the same clean-room discipline as the OS corpus — it must not become a copy of Wappalyzer's dataset (C-001).
- **Notes.** Completes [IMP-010](#imp-010-fold-web-tech-fingerprinting-into-scans). Test `user_corpus_layers_over_builtin_without_a_rebuild`; example at `examples/web-corpus.json`; live-verified (an `htmx` rule fired via `--web-corpus`).

### IMP-002: Support an NVD API key (and backoff) on the CVE-matching path

- **Status:** applied (2026-06-28)
- **Found:** 2026-06-26, during F-015 development.
- **Location:** [crates/pontus-core/src/intel.rs](../crates/pontus-core/src/intel.rs) — `http_get`.
- **Effort:** small
- **Description.** Anonymous NVD access is rate-limited (~5 requests / 30 s), so assessing many products throttled or dropped enrichment ([BUG-004](BUGS.md)).
- **Proposal.** Send an `NVD_API_KEY` (from the environment) as the `apiKey` header on NVD requests, and retry HTTP 403/429/503 with exponential backoff (1/2/4/8 s, up to 4 attempts); also add a 20 s per-request timeout so a slow feed can't hang a scan.
- **Trade-offs.** The key is optional, so the offline-friendly default (D-009) is unchanged; backoff lengthens a throttled scan but stops it failing outright.
- **Notes.** Fixes [BUG-004](BUGS.md). Pure-Rust (`ureq`), no new dependency.

### IMP-003: Surface match confidence for version-less CVE findings

- **Status:** applied (2026-06-28)
- **Found:** 2026-06-26, while fixing BUG-001.
- **Location:** [crates/pontus-core/src/intel.rs](../crates/pontus-core/src/intel.rs) (`Vuln`/`assess`), [crates/pontus-core/src/store.rs](../crates/pontus-core/src/store.rs) (`vulns` column + `risk_ranked`), the risk view (CLI + GUI).
- **Effort:** medium
- **Description.** A version-less detection yields a product-wide CPE match (every CVE for the product), over-reporting ([BUG-002](BUGS.md)); these were shown identically to version-accurate findings.
- **Proposal.** Carry a `version_matched` flag from `assess` through a new `vulns.version_matched` column (idempotent migration) and `risk_ranked`/`pontus_risk_json` to the views: a "Match: exact / product-wide" column in the GUI risk table (amber + tooltip for product-wide) and a "(product-wide)" marker on the CLI's top finding. Mark, not suppress.
- **Trade-offs.** Adds a column to the vuln model and a view column; deliberately does not de-weight the score (the first cut marks, so a genuinely-exploited product isn't hidden).
- **Notes.** Surfaces (does not eliminate) [BUG-002](BUGS.md) — product-wide matching is inherent without a version. Tests `risk_ranked_carries_version_matched_flag`.

### IMP-016: Distinguish UDP open|filtered from confirmed-open in the heatmap

- **Status:** applied (2026-06-27)
- **Found:** 2026-06-27 — comparing two scans' heatmaps, UDP bands flickered, because `open|filtered` (no reply) was painted the same green as a confirmed-open port.
- **Location:** [gui/src/heatmapdialog.cpp](../gui/src/heatmapdialog.cpp).
- **Effort:** small
- **Description.** A UDP probe with no reply is recorded as `open|filtered` — *unconfirmed* (could be open or filtered), and inherently non-deterministic across scans. The heatmap showed it identically to a confirmed-open service, making UDP look inconsistent and overstating exposure.
- **Proposal.** Track per cell whether the port is confirmed (TCP, or UDP with a real response) vs `open|filtered`, and render confirmed in green, `open|filtered` in amber, with a legend and matching tooltips.
- **Trade-offs.** A second colour to read, but the distinction is the point — solid bands are real exposure, amber is "no answer."
- **Notes.** Doesn't change the data, only its honesty in the view. The larger cross-scan differences the user noticed were genuine host churn (devices asleep), best seen in the Drift/diff view — not a bug.

### IMP-015: Feed web-tech fingerprints into vulnerability assessment

- **Status:** applied (2026-06-27)
- **Found:** 2026-06-27 — a GUI scan with `--assess-vulns --inspect` but the *native* detector recorded no CVEs, because the native detector can't name an HTTP product (an HTTP server sends nothing on a bare connect), and `--inspect`'s web-tech result (which *does* identify nginx) wasn't reaching the assessor.
- **Location:** [crates/pontus-cli/src/main.rs](../crates/pontus-cli/src/main.rs) — the `--assess-vulns` loop.
- **Effort:** small
- **Description.** `--assess-vulns` only assessed the service detector's products. With the clean-room native detector that meant web servers were never matched, so users needed `--detector nmap` to get web CVEs.
- **Proposal.** Also assess the web technologies attached to each port by `--inspect`, deduped with the detector's products; `record_vuln`'s `INSERT OR IGNORE` collapses any overlap. So native + `--inspect` now yields web-server CVEs with no nmap dependency.
- **Trade-offs.** More NVD lookups per scan (nginx, jQuery, Bootstrap, …) — paced by the per-product cache and gated behind `--assess-vulns`; a bogus product just returns 0.
- **Notes.** Live-verified: `scan --assess-vulns --inspect` (native) now prints `vulns <port>: <tech> → N CVE(s)` for web-tech findings. Pairs with IMP-014 (the GUI can now run this combination).

### IMP-014: Expose the richer scan options in the GUI New-scan dialog

- **Status:** applied (2026-06-27)
- **Found:** 2026-06-27 — a GUI scan found far fewer services than a terminal scan, because the dialog only offered a subset of the CLI's options.
- **Location:** [gui/src/scandialog.cpp](../gui/src/scandialog.cpp), [gui/src/scandialog.h](../gui/src/scandialog.h).
- **Effort:** medium
- **Description.** The New-scan dialog exposed targets/scope/TCP ports/UDP ports/db/operator/skip-rDNS, but not `--top-ports`, `--detector`, `--assess-vulns` or `--inspect` — so GUI scans were narrow and unenriched, the cause behind the "GUI scanning is broken" reports.
- **Proposal.** Add a Top-ports field, a Detector dropdown (native / nmap), and Assess-vulnerabilities / Deep-inspect checkboxes; thread them into the shelled-out command (D-008) and persist them in the saved profiles.
- **Trade-offs.** More dialog surface, and the enrichment options lengthen scans / hit the network — so they default off with labels saying so. `--os-detector nmap` (needs sudo) is deliberately left out for now.
- **Notes.** Pure GUI plumbing over existing CLI options. Pairs with BUG-010 — a GUI scan can now cover broad ports *and* TLS/web/vuln enrichment, so the heatmap and risk views populate from a GUI-launched scan, consistently.

### IMP-013: Port-range syntax and a top-ports preset

- **Status:** applied (2026-06-27)
- **Found:** 2026-06-27, noticing the heatmap only ever shows the few ports a scan explicitly lists.
- **Location:** [crates/pontus-cli/src/main.rs](../crates/pontus-cli/src/main.rs) — `parse_ports`, `resolve_ports`, `TOP_PORTS`, the `--top-ports` flag.
- **Effort:** small
- **Description.** `parse_ports` accepted only a comma list of single ports — no ranges, no all-ports — so broad scanning was impractical and most real services were never probed.
- **Proposal.** Extend `parse_ports` to accept ranges and `-` (all of 1–65535), mixed and de-duplicated (`80,443,8000-8100`, `1-1024`, `-`); add `--top-ports <N>` over a curated clean-room common-ports list (`TOP_PORTS`), unioned with `--ports`. The range syntax applies to `--udp-ports` too (same parser).
- **Trade-offs.** Wide scans are slower/noisier, so breadth stays opt-in and the default is unchanged; `-` against /24 is fine because scope still bounds the hosts.
- **Notes.** `TOP_PORTS` is written from public well-known-port knowledge, not Nmap's frequency data (C-001). Six unit tests on `parse_ports`/`resolve_ports`; live-verified a range scan (`8078-8082` → found 8080). Port 0 is dropped.

### IMP-012: Dedupe the risk view's per-host CVE list by CVE

- **Status:** applied (2026-06-27)
- **Found:** 2026-06-27, reviewing a populated risk view — a web server on 80 and 443 listed each CVE twice, inflating the count (82 = 41 × 2 ports).
- **Location:** [crates/pontus-core/src/store.rs](../crates/pontus-core/src/store.rs) — `risk_ranked`.
- **Effort:** trivial
- **Description.** Vulnerabilities are recorded per port, so a product on multiple ports produced duplicate CVE rows in the (CVE-centric) triage view.
- **Proposal.** Collapse each host's vulns to one entry per CVE in `risk_ranked` — the single scoring path, so the CLI `risk`, FFI and GUI all dedupe consistently. The host risk (the max) is unchanged.
- **Trade-offs.** Drops the which-ports detail from the view; acceptable since you fix a CVE once, not per port, and the per-port rows remain in the `vulns` table.
- **Notes.** Test `risk_ranked_dedupes_a_cve_recorded_on_multiple_ports`. Surfaced reviewing the IMP-008/010 work.

### IMP-008: Integrate TLS inspection into the scan / observation model

- **Status:** applied (2026-06-27)
- **Found:** 2026-06-27, implementing F-016 as a standalone `tls` command.
- **Location:** [crates/pontus-core/src/model.rs](../crates/pontus-core/src/model.rs) (`TlsObservation`), [crates/pontus-cli/src/main.rs](../crates/pontus-cli/src/main.rs) (`scan --inspect`), [gui/src/mainwindow.cpp](../gui/src/mainwindow.cpp).
- **Effort:** medium
- **Description.** `pontus-cli tls <host>` printed a report but recorded nothing against the asset, so TLS findings didn't participate in the inventory.
- **Proposal.** Add a `TlsObservation` to `PortObservation` (JSON in the observation `state`, no migration); during `scan --inspect`, run `tls::inspect` on open TLS ports (443/8443) and attach the summary (protocols, weak ciphers, cert subject/expiry/self-signed, findings); surface it in the GUI asset-detail "Deep inspection" panel.
- **Trade-offs.** Inspection adds handshakes per TLS port, so it is opt-in (`--inspect`). The compact summary keeps the observation small; full detail stays in the `tls` command.
- **Notes.** Stored as JSON state like `os_guess` (D-007's lightweight shape). Flows through `assets`/history FFI with no FFI change. Pairs with [IMP-004](#imp-004-surface-the-os-guess-in-the-gui-inventory).

### IMP-010: Fold web-tech fingerprinting into scans

- **Status:** applied (2026-06-27)
- **Found:** 2026-06-27, implementing F-017 as a standalone `http` command.
- **Location:** [crates/pontus-core/src/model.rs](../crates/pontus-core/src/model.rs) (`TechObservation`), [crates/pontus-cli/src/main.rs](../crates/pontus-cli/src/main.rs) (`scan --inspect`), [gui/src/mainwindow.cpp](../gui/src/mainwindow.cpp).
- **Effort:** medium
- **Description.** `pontus-cli http <host>` fingerprinted one endpoint but recorded nothing against the asset.
- **Proposal.** Add `TechObservation`s to `PortObservation`; during `scan --inspect`, run `webtech::fingerprint` on open HTTP(S) ports (80/443/8080/8000/8443) and attach the detected technologies; surface them in the GUI deep-inspection panel.
- **Trade-offs.** Fetching pages adds latency, so it shares the opt-in `--inspect` gate with TLS.
- **Notes.** The "updatable signature file" half of the original idea (a JSON corpus mirroring `OsCorpus`) is **not** done — split out as [IMP-011](#imp-011-updatable-web-tech-signature-file). Stored as JSON state; no FFI change.

### IMP-004: Surface the OS guess in the GUI inventory

- **Status:** applied (2026-06-27)
- **Found:** 2026-06-26, implementing F-013.
- **Location:** [crates/pontus-core/src/store.rs](../crates/pontus-core/src/store.rs) (`AssetSummary`/`list_assets`), [gui/src/mainwindow.cpp](../gui/src/mainwindow.cpp).
- **Effort:** small
- **Description.** `scan` records an `os_guess` per observation, but the GUI did not display it.
- **Proposal.** Add the most-recent observation's OS guess to `AssetSummary` (via a `json_extract` subquery over the observation `state`), so it flows through `assets_json`; show it as an "OS" column in the inventory and an "OS" column in the per-asset observation history.
- **Trade-offs.** One more column in an already-wide table; kept compact (dash when unknown) and the inventory remains sortable.
- **Notes.** Read-side over data the store already holds (F-013, D-011). The `json_extract` uses the bundled SQLite's JSON1 extension. Pairs with [IMP-008](#imp-008-integrate-tls-inspection-into-the-scan--observation-model)/[IMP-010](#imp-010-fold-web-tech-fingerprinting-into-scans-with-an-updatable-signature-set) for the rest of the deep-inspection surfacing.

### IMP-006: Capture the ICMP echo-reply TTL so portless hosts get an OS guess

- **Status:** applied (2026-06-26)
- **Found:** 2026-06-26, live-verifying F-013 — only the one host with open ports (the router) received a guess.
- **Location:** [crates/pontus-core/src/discovery/packet.rs](../crates/pontus-core/src/discovery/packet.rs) (`EchoReply`), [crates/pontus-core/src/discovery/icmp.rs](../crates/pontus-core/src/discovery/icmp.rs), [crates/pontus-core/src/discovery/mod.rs](../crates/pontus-core/src/discovery/mod.rs) (`DiscoveredHost`, `merge_hosts`), [crates/pontus-cli/src/main.rs](../crates/pontus-cli/src/main.rs).
- **Effort:** small
- **Description.** The OS fingerprint's TTL signal was read only from the TCP SYN-ACK, so a host with no open scanned ports yielded no TTL and no guess — even when it answered ICMP echo, whose reply carries the same initial-TTL signal. On a typical subnet most hosts have no open ports, so coverage was thin.
- **Proposal.** Read the IP-header TTL of the ICMP echo reply in the v4 discovery sweep (`EchoReply::ttl`), carry it on `DiscoveredHost`, preserve it through `merge_hosts` when an ARP hit supersedes the ICMP one, and feed it into `OsSignals` — the CLI prefers the SYN-ACK TTL and falls back to the echo TTL.
- **Trade-offs.** Adds a field to `EchoReply`/`DiscoveredHost` and a little parsing to the ICMP path; the ARP-only path still yields no TTL (ARP has no IP header), so link-local devices that ignore ICMP remain banner-only. IPv6 still lacks the signal ([BUG-005](BUGS.md)).
- **Notes.** Extends D-011. Regression test `icmpv4_reply_unwraps_ip_header` now asserts the TTL is captured. Independent of [IMP-004](#imp-004-surface-the-os-guess-in-the-gui-inventory) and [IMP-005](#imp-005-use-the-tcp-window-and-consider-an-active-probe-to-refine-os-family).

### IMP-001: One shared host-risk scoring path for CLI, FFI and GUI

- **Status:** applied (2026-06-26)
- **Found:** 2026-06-26, building the GUI risk view (F-015).
- **Location:** [crates/pontus-core/src/store.rs](../crates/pontus-core/src/store.rs) (`risk_ranked`), [crates/pontus-cli/src/main.rs](../crates/pontus-cli/src/main.rs) (`print_risk`).
- **Effort:** small
- **Description.** The CLI's `risk` command grouped a scan's vulns by host, scored them and ranked them inline. The GUI needed the identical computation, which would have duplicated the C-002 scoring logic in a second place and let the two drift.
- **Proposal.** Hoist the grouping/scoring/ranking into `store::risk_ranked`, returning serializable `HostRisk`/`RankedVuln`; have the CLI, the FFI (`pontus_risk_json`) and the GUI all consume it.
- **Trade-offs.** `store` now calls into `intel` scoring — but it already depended on `intel::Vuln` for `record_vuln`, so no new coupling. The alternative (scoring in the FFI layer) would have left the CLI path separate and unshared.
- **Notes.** Landed with the GUI risk view; removed the CLI's duplicated grouping and the now-unused `HostRiskRow`. Surfaced no bugs.
