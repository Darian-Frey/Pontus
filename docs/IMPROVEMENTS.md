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

### IMP-004: Surface the OS guess in the GUI inventory

- **Status:** suggested
- **Found:** 2026-06-26, implementing F-013.
- **Location:** [gui/src/mainwindow.cpp](../gui/src/mainwindow.cpp) (asset table + detail pane).
- **Effort:** small
- **Description.** `scan` now records an `os_guess` per observation, and it already flows through `pontus_asset_history_json`, but the GUI does not display it. The inventory could show an OS column and the detail pane an "OS: Linux/Unix (Ubuntu)" line.
- **Proposal.** Read `os_guess` from the observation state in the asset history JSON; add an OS column to the asset table (most-recent observation) and a line in the detail pane.
- **Trade-offs.** Another column competes for horizontal space in an already-wide table; mitigated by making it sortable/hideable, or showing OS only in the detail pane initially.
- **Notes.** Pure GUI read-side work over data the store already holds (F-013, D-011). No core/FFI change needed.

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

## Applied

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
