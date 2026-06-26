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
- **Notes:** Inherent to CPE applicability matching without a version — not a coding defect. Candidate mitigation tracked as [IMP-003](IMPROVEMENTS.md) (flag version-less findings as low-confidence in the risk view rather than suppressing them). Deferred pending a decision on how to surface match confidence.

### BUG-004: NVD anonymous rate limiting can throttle or fail enrichment on large scans

- **Status:** deferred
- **Found:** 2026-06-26, observed during F-015 development.
- **Location:** [crates/pontus-core/src/intel.rs](../crates/pontus-core/src/intel.rs) — `fetch_nvd` / `resolve_cpe`.
- **Severity:** Low — affects scan throughput and completeness on large estates, not correctness of what is matched.
- **Description:** The NVD CPE and CVE APIs rate-limit anonymous clients (~5 requests / 30 s). A scan assessing many distinct products issues a request per product (deduped via the CLI's `vuln_cache`), so a large estate can be throttled, slowing assessment or dropping enrichment for some services.
- **Reproduction:** Run `scan --assess-vulns` against a subnet with many distinct detected products and observe pacing/HTTP 403s from the NVD API.
- **Notes:** Mitigated today by per-product caching. Candidate improvement tracked as [IMP-002](IMPROVEMENTS.md) (support an `NVD_API_KEY` for the higher rate limit, plus backoff/retry on 403/429). Consistent with D-009 (NVD queried on demand).
