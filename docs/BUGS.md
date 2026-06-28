> **Status:** Active
> **Provenance:** Shane Hartley (architect); Claude (bug logging) — 2026-06-26
> **Last reviewed:** 2026-06-26
> **Why this status:** In-repo defect log adopted mid-Phase 3 (adopting decision to be recorded as a `D-NNN` in ARCHITECTURE.md). Seeded with the realised bugs and open limitations from the F-015 work; maintained continuously per Maintenance Rule 8 ("log when found, not silently fixed").

# Bugs

Catalogue of bugs discovered during development. Per the project workflow, bugs
are **logged here when found, not silently fixed** — the author (Shane) decides
whether to act immediately, defer, or decline. This is the backward-looking
incident log (what actually went wrong), the dual of a forward-looking
`ATTACK_VECTORS.md` checklist (which Pontus has not yet adopted — `AV-NNN` is
reserved).

`BUG-NNN` IDs are append-only and never renumbered; superseded entries keep their
ID with a status flag. Entries are filed under their current status; the
`Status:` line is the source of truth. Fixed bugs cross-reference the
`### Fixed` entry in [CHANGELOG.md](../CHANGELOG.md).

## Open

_None._

## Fixed

### BUG-001: NVD CPE vendor resolution picked an obsolete vendor, hiding CVEs

- **Status:** fixed (2026-06-26)
- **Found:** 2026-06-26, during F-015 live testing on a reference /24 (the router's nginx assessed to zero vulnerabilities).
- **Location:** [crates/pontus-core/src/intel.rs](../crates/pontus-core/src/intel.rs) — `resolve_cpe` / `parse_cpe`.
- **Severity:** High — silent under-reporting of vulnerabilities is the opposite of what a triage tool must do; a vulnerable host presented as clean.
- **Description:** A product whose CPE entries span multiple vendors (e.g. nginx, listed under `igor_sysoev`, `nginx` and `f5`) resolved to the first vendor the NVD CPE API returned (oldest-first), which carried few or no CVEs. The exact-product match then queried the wrong vendor and returned an empty or partial CVE set.
- **Reproduction:** Detect nginx with no version (e.g. `--detector nmap` against a host whose server banner omits the version) and run `scan --assess-vulns`; before the fix the host recorded 0 vulns.
- **Notes:** Fixed in two steps — pick the **most-frequent** `(vendor, product)` pair across exact-product matches, then read the **full** CPE result page (`resultsPerPage=10000`) so the whole vendor distribution is sampled (`f5` wins for nginx). Surfaced the inherent imprecision of version-less matching → BUG-002 (deferred).

### BUG-003: GUI build linked a stale FFI library after a debug→release switch

- **Status:** fixed (2026-06-26)
- **Found:** 2026-06-26, building the GUI risk view — the link failed with `undefined reference to pontus_risk_json` even though the release `.so` exported it.
- **Location:** [gui/CMakeLists.txt](../gui/CMakeLists.txt).
- **Severity:** Medium — build breakage; previously also manifested as a runtime `undefined symbol` when a stale `.so` happened to link.
- **Description:** `find_library(PONTUS_FFI_LIB …)` caches its result independently of `PONTUS_TARGET_DIR`. Configuring a debug build and later reconfiguring for release kept the cached `target/debug` path, so the GUI linked the stale debug library (missing newly-added symbols).
- **Reproduction:** Configure the GUI once against `target/debug`, then reconfigure with `-DPONTUS_TARGET_DIR=…/target/release`; the link still resolves against the debug `.so`.
- **Notes:** Fixed by constructing the library path directly from `PONTUS_TARGET_DIR` (with an existence check) instead of `find_library`. Recorded under CHANGELOG `### Fixed`.

### BUG-006: OS fingerprint reported 100% confidence for a lone TTL signal

- **Status:** fixed (2026-06-26)
- **Found:** 2026-06-26, live-verifying F-013 — every TTL-only host on the reference /24 reported "Linux/Unix (100%)", which looked too certain.
- **Location:** [crates/pontus-core/src/os.rs](../crates/pontus-core/src/os.rs) — `fingerprint`.
- **Severity:** Medium — the *family* was correct (all the responders were genuinely Unix-like), but the confidence was dishonest: a single broad signal presented as certainty undermines trust in the score.
- **Description:** Confidence was computed as the winning family's share of all matched weight. With only a TTL rule matching, that share is 1/1 = 100% — conflating "only one rule fired" with "certain", even though TTL 64 is the least discriminating signal (it only rules out Windows and old network gear).
- **Reproduction:** Scan a host that responds with initial TTL 64 and no recognised service banner; before the fix the OS guess read "100%".
- **Notes:** Fixed by blending _agreement_ (share of matched weight, which drops on conflicting signals) with a saturating _evidence-strength_ term, so a lone TTL match caps at 0.5 and a corroborating banner climbs higher. Regression tests `ttl_only_is_a_weak_guess_not_certainty` and `banner_pins_a_distro_and_raises_confidence_above_ttl_only`.

### BUG-007: SYN probe carried no TCP options, so every host's option layout read as "M"

- **Status:** fixed (2026-06-26)
- **Found:** 2026-06-26, live-verifying F-013 — a host known to run Linux returned the option layout `M` (MSS only), the same as every other host, defeating the stack-signature discriminator.
- **Location:** [crates/pontus-core/src/scan/tcp.rs](../crates/pontus-core/src/scan/tcp.rs) — `build_syn_v4` / `build_syn_v6`.
- **Severity:** High (for F-013) — it silently neutered the strongest passive OS signal: the option layout looked identical for all operating systems, so nothing could be distinguished beyond TTL.
- **Description:** SACK-permitted, Timestamp and Window-scale appear in a SYN-ACK only if the client's SYN advertised them first. The sweep's SYN was a bare 20-byte header with no options, so every responder — Linux, Windows, the router — replied with only an MSS option, and every `opts_layout` collapsed to `M`. The bug masqueraded as targets having "minimal stacks".
- **Reproduction:** Run a service on a known-Linux host and scan it; before the fix the recorded stack signature was `opts=M` despite a full modern TCP stack.
- **Notes:** Fixed by having `build_syn_v4`/`build_syn_v6` carry a representative option set (MSS, SACK-permitted, Timestamp, NOP, Window-scale) — the same reason nmap/p0f probes include options. Responders now echo their own option ordering. Regression test `syn_probe_carries_the_fingerprint_options`.

### BUG-008: KEV cache not found under sudo (root's cache dir, not the user's)

- **Status:** fixed (2026-06-27)
- **Found:** 2026-06-27, running `sudo pontus-cli scan --assess-vulns` after `pontus-cli intel update` — "no KEV cache at /root/.cache/pontus/kev.json".
- **Location:** [crates/pontus-cli/src/main.rs](../crates/pontus-cli/src/main.rs) — `default_cache_dir`.
- **Severity:** Medium — KEV enrichment silently does nothing under a privileged scan, so KEV-listed vulnerabilities aren't flagged as such (skewing the risk ranking).
- **Description:** Raw-socket scans run under sudo (HOME=/root), but `intel update` is run as the user, caching to `~/.cache/pontus`. The privileged scan resolved the cache from root's HOME and missed it.
- **Reproduction:** `pontus-cli intel update` as the user, then `sudo pontus-cli scan … --assess-vulns`; the KEV cache is reported missing.
- **Notes:** Fixed by preferring the invoking user's cache (`/home/$SUDO_USER/.cache/pontus`) when `SUDO_USER` is set, before falling back to `HOME`. Does not by itself explain an empty risk view — KEV absence only drops the `kev` flag, not the NVD-matched CVEs (see BUG-009).

### BUG-009: Vulnerability assessment failures were silent

- **Status:** fixed (2026-06-27)
- **Found:** 2026-06-27, a `--assess-vulns` scan recorded no vulnerabilities for a host whose service was detected, with no explanation.
- **Location:** [crates/pontus-cli/src/main.rs](../crates/pontus-cli/src/main.rs) — the `--assess-vulns` loop.
- **Severity:** Medium — a failed NVD lookup or a product detected without a version both produced "no vulnerabilities" indistinguishably, masking the real cause.
- **Description:** `intel::assess(...).unwrap_or_default()` swallowed any error (NVD network/rate-limit) to an empty result, and ports whose service had no product were skipped without a word, so a "no vulns" outcome gave no diagnostic.
- **Reproduction:** Run `--assess-vulns` while NVD is unreachable, or against a host whose detector yields no product; the result is silently empty.
- **Notes:** Fixed by reporting each assessment (`vulns <port>: <product> <version> → N CVE(s)`) and printing a note when `assess` errors instead of discarding it. Surfacing, not behaviour, changed.

### BUG-010: Heatmap mixed each host's latest observation across scans

- **Status:** fixed (2026-06-27)
- **Found:** 2026-06-27, GUI heatmap looked inconsistent — different hosts showed ports from different scans, so a host last scanned with a narrow port set appeared to have *lost* services it still exposes.
- **Location:** [gui/src/heatmapdialog.cpp](../gui/src/heatmapdialog.cpp); new FFI `pontus_observations_json`.
- **Severity:** Medium — a misleading inventory view that read as flaky scanning.
- **Description:** The heatmap built its grid from each asset's *latest observation*. Those come from different scans with different port coverage (and different up/down states), so it conflated heterogeneous data — the router scanned narrowly in the latest scan showed fewer ports than an IoT host whose latest observation was an earlier broad scan.
- **Reproduction:** Scan a /24 broadly, then scan it again with a narrow `--ports` set; open the heatmap — hosts display ports from whichever scan last observed them, not a single coherent snapshot.
- **Notes:** Fixed by scoping the heatmap to a single scan via a selector (default latest), over a new `pontus_observations_json(scan_id)` FFI (serialising `observations_for_scan`). Now every host is compared on the same port coverage, matching the scan-scoped risk and diff views. The narrower *cause* — GUI scans use fewer options than the CLI — is tracked as [IMP-014](IMPROVEMENTS.md).

### BUG-011: Wide scans aborted on ENOBUFS (transmit-queue backpressure)

- **Status:** fixed (2026-06-27)
- **Found:** 2026-06-27, a `/24` scan with `--top-ports 100` (~25k SYN packets) failed immediately with "discovery I/O error: No buffer space available (os error 105)".
- **Location:** [crates/pontus-core/src/raw.rs](../crates/pontus-core/src/raw.rs) — `BatchSender::send`, `send_to`.
- **Severity:** High — a sufficiently wide scan (many hosts × many ports) failed entirely, so broad scanning (the whole point of IMP-013) was unusable.
- **Description:** The raw-socket send path treated only `WouldBlock` as backpressure; `ENOBUFS` (the kernel's transmit queue momentarily full under a fast wide sweep) fell through to the fatal-error arm and aborted the scan, even though it is transient and recoverable.
- **Reproduction:** Scan a `/24` with ~100 ports (≈25k SYN packets) fast enough to fill the qdisc; the sweep returns os error 105.
- **Notes:** Fixed by classifying `ENOBUFS` as backpressure (`is_backpressure`) and pacing-then-retrying (200µs), dropping a single probe only after ~64 sustained retries so the sweep continues rather than failing. Unit test `enobufs_is_classified_as_backpressure`. The message said "discovery" because `ScanError` aliases `DiscoveryError`, so a SYN-sweep I/O error reuses the discovery wording — a clearer label would be a small follow-up.

### BUG-012: One physical host could appear twice (IP-anchored + MAC-anchored)

- **Status:** fixed (2026-06-28)
- **Found:** 2026-06-28, on the reference /24 — hosts `.119` and `.169` each showed as two inventory rows with different OS guesses (one MAC-anchored, one IP-anchored).
- **Location:** [crates/pontus-core/src/identity.rs](../crates/pontus-core/src/identity.rs) — `resolve`, the bare-IP fallback.
- **Severity:** Medium — a duplicate asset double-counts a host and splits its observation history, undermining drift/baseline and the single-source-of-truth inventory (D-007). No data loss; both rows hold real observations.
- **Description:** The bare-IP fallback only matched an asset that was _itself_ IP-anchored (`identity_kind = 'ip'`). So a host first seen via ARP (MAC-anchored) and later seen via ICMP only (ARP didn't fire that scan, so the sighting carried no MAC) failed to resolve to its existing asset and forked a second, IP-anchored one. ARP timing on intermittently-responsive devices (Cast/IoT) made this common.
- **Reproduction:** Record a host with a MAC, then record the same IP with no MAC (`sig(None, ip)`) — before the fix, two assets; after, one (`icmp_only_sighting_after_arp_resolves_to_the_same_asset`).
- **Notes:** Fixed by splitting the fallback (C-003-adjacent, so deliberately narrow). A **genuinely bare-IP** sighting (no MAC/host-key/hostname) now attaches to whichever asset already lives at that address, most-recent-first so a recycled lease resolves to its present tenant, regardless of anchor — IP remains a _locator_, never an _anchor_ (`merge` re-derives the anchor from the strongest stored field). A sighting that _does_ carry a stronger-but-unmatched signal (a new MAC) is still treated as a new host and may only _promote_ an existing IP-anchored asset, so recycled-address hosts stay distinct (`a_distinct_mac_at_a_known_ip_stays_its_own_asset`). **Prevention only:** existing duplicates cannot be merged retroactively — the append-only trigger (D-007) forbids re-pointing or deleting their observations — so they persist as historical artefacts and go stale once the fix routes new sightings to the canonical asset. Reversal condition in the code comment. Three new tests in `asset_store.rs`.

### BUG-004: NVD anonymous rate limiting can throttle or fail enrichment on large scans

- **Status:** fixed (2026-06-28)
- **Found:** 2026-06-26, observed during F-015 development.
- **Location:** [crates/pontus-core/src/intel.rs](../crates/pontus-core/src/intel.rs) — `http_get`.
- **Severity:** Low — affected scan throughput and completeness on large estates, not correctness of what was matched.
- **Description:** The NVD CPE and CVE APIs rate-limit anonymous clients (~5 requests / 30 s). A scan assessing many distinct products issues a request per product, so a large estate could be throttled — slowing assessment or dropping enrichment for some services.
- **Reproduction:** Run `scan --assess-vulns` against a subnet with many distinct products and observe pacing / HTTP 403s from NVD.
- **Notes:** Fixed via [IMP-002](IMPROVEMENTS.md): an optional `NVD_API_KEY` raises the limit, and 403/429/503 are retried with exponential backoff instead of failing. Per-product caching still reduces the request count.

## Won't Fix

_None._

## Deferred

### BUG-002: Version-less CVE matching is product-wide and over-reports

- **Status:** deferred
- **Found:** 2026-06-26, while fixing BUG-001.
- **Location:** [crates/pontus-core/src/intel.rs](../crates/pontus-core/src/intel.rs) — `fetch_nvd` / `assess`.
- **Severity:** Medium — noisy rather than dangerous: it over-reports (lists CVEs across all versions of a product) rather than under-reporting, but it dilutes the "fix-this-first" signal for services detected without a version.
- **Description:** When the detector reports a product with no version (e.g. nginx with a version-suppressed banner), the CPE `virtualMatchString` cannot constrain by version, so every CVE ever filed against the product matches. Version-present matching (e.g. OpenSSH 8.2p1) is precise; version-absent matching is product-wide.
- **Reproduction:** Assess a service detected with a product but no version and compare the CVE count against the same product pinned to a single version.
- **Notes:** Inherent to CPE applicability matching without a version — not a coding defect; deliberately stays deferred (it can't be eliminated without version data). **Now surfaced** by [IMP-003](IMPROVEMENTS.md) (applied): version-less findings are flagged "product-wide" in the risk view, so the over-reporting is visible and discountable rather than silently inflating the count.

### BUG-005: IPv6 OS fingerprinting has no TTL/hop-limit signal

- **Status:** deferred
- **Found:** 2026-06-26, implementing F-013.
- **Location:** [crates/pontus-core/src/scan/tcp.rs](../crates/pontus-core/src/scan/tcp.rs) — `parse_tcp_reply_v6`.
- **Severity:** Low — IPv6 OS guesses are weaker (banner-only), not wrong; IPv4 is unaffected.
- **Description:** On a raw IPv6 TCP socket the kernel strips the IPv6 header before delivering the segment, so the SYN-ACK's hop limit is not in the receive buffer. `parse_tcp_reply_v6` therefore reports `ttl: None`, and the OS fingerprint for a v6-only host rests on volunteered banners alone — losing the initial-TTL family signal that v4 enjoys (D-011).
- **Reproduction:** Scan an IPv6 host whose services suppress OS tokens in their banners; the recorded `os_guess` is absent even though a v4 scan of an equivalent host would bucket it by TTL.
- **Notes:** The hop limit is recoverable via the `IPV6_RECVHOPLIMIT` socket option and `recvmsg` ancillary data, or by reading it from an `AF_PACKET` capture. Deferred — a socket-plumbing change for a secondary signal on the less-common path. Related to the IPv6 traceroute hop-limit follow-up noted for F-009.
