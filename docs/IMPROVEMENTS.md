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

## Applied

### IMP-001: One shared host-risk scoring path for CLI, FFI and GUI

- **Status:** applied (2026-06-26)
- **Found:** 2026-06-26, building the GUI risk view (F-015).
- **Location:** [crates/pontus-core/src/store.rs](../crates/pontus-core/src/store.rs) (`risk_ranked`), [crates/pontus-cli/src/main.rs](../crates/pontus-cli/src/main.rs) (`print_risk`).
- **Effort:** small
- **Description.** The CLI's `risk` command grouped a scan's vulns by host, scored them and ranked them inline. The GUI needed the identical computation, which would have duplicated the C-002 scoring logic in a second place and let the two drift.
- **Proposal.** Hoist the grouping/scoring/ranking into `store::risk_ranked`, returning serializable `HostRisk`/`RankedVuln`; have the CLI, the FFI (`pontus_risk_json`) and the GUI all consume it.
- **Trade-offs.** `store` now calls into `intel` scoring — but it already depended on `intel::Vuln` for `record_vuln`, so no new coupling. The alternative (scoring in the FFI layer) would have left the CLI path separate and unshared.
- **Notes.** Landed with the GUI risk view; removed the CLI's duplicated grouping and the now-unused `HostRiskRow`. Surfaced no bugs.
