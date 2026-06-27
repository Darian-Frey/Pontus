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

### IMP-002: Support an NVD API key (and backoff) on the CVE-matching path

- **Status:** suggested
- **Found:** 2026-06-26, during F-015 development.
- **Location:** [crates/pontus-core/src/intel.rs](../crates/pontus-core/src/intel.rs) — `resolve_cpe` / `fetch_nvd` / `http_get`.
- **Effort:** small
- **Description.** Anonymous NVD API access is rate-limited to ~5 requests / 30 s ([BUG-004](BUGS.md)), so assessing many distinct products throttles or drops enrichment. NVD grants a much higher limit to clients sending an `apiKey`.
- **Proposal.** Read an `NVD_API_KEY` environment variable; when set, send it as the `apiKey` header on CPE/CVE requests. Add bounded exponential backoff with retry on HTTP 403/429 regardless of key.
- **Trade-offs.** Adds a configuration knob and key-management surface (documenting where to obtain a key); the key is optional, so the default offline-friendly posture (D-009) is unchanged. Backoff lengthens worst-case scan time but prevents outright enrichment loss.
- **Notes.** Directly mitigates [BUG-004](BUGS.md). Consistent with D-009 (NVD queried on demand).

### IMP-003: Surface match confidence for version-less CVE findings

- **Status:** suggested
- **Found:** 2026-06-26, while fixing BUG-001.
- **Location:** [crates/pontus-core/src/intel.rs](../crates/pontus-core/src/intel.rs), [crates/pontus-core/src/store.rs](../crates/pontus-core/src/store.rs) (`risk_ranked`), and the GUI risk view.
- **Effort:** medium
- **Description.** When a service is detected without a version, CPE matching is product-wide and over-reports ([BUG-002](BUGS.md)). The risk view currently presents these the same as version-accurate findings, diluting the "fix-this-first" signal.
- **Proposal.** Record whether a match was version-constrained, carry a confidence flag through `risk_ranked`/`pontus_risk_json`, and mark version-less findings in the CLI and GUI (e.g. a "product-wide" badge), optionally de-weighting them in the score.
- **Trade-offs.** Adds a confidence dimension to the vuln data model and the FFI/GUI surface; de-weighting risks hiding a genuinely exploited product if tuned too aggressively, so the first cut should mark, not suppress.
- **Notes.** Addresses [BUG-002](BUGS.md). Depends on no other work.

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

### IMP-011: Updatable web-tech signature file

- **Status:** suggested
- **Found:** 2026-06-27, splitting the unfinished half of IMP-010.
- **Location:** [crates/pontus-core/src/webtech.rs](../crates/pontus-core/src/webtech.rs).
- **Effort:** medium
- **Description.** The web-tech signature set is compiled-in, unlike the OS corpus which a `--os-corpus` file extends without a rebuild. Community coverage would grow faster from a layerable signature file.
- **Proposal.** Lift the header/cookie/body signatures into a JSON schema and load a user file over the built-in defaults (mirroring `OsCorpus::load`), with a `--web-corpus` flag on the relevant commands.
- **Trade-offs.** An external file invites the same clean-room discipline as the OS corpus — it must not become a copy of Wappalyzer's dataset (C-001) — and adds a schema to maintain.
- **Notes.** The remaining half of [IMP-010](#imp-010-fold-web-tech-fingerprinting-into-scans); mirrors the `OsCorpus` design.

## Applied

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
