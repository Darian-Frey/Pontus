//! Vulnerability intelligence (F-015): match → enrich → triage.
//!
//! The load-bearing idea (C-002) is that **exploitation likelihood, not raw
//! severity, drives triage**. A CVE list sorted by CVSS over-reports urgency; the
//! signals that make it actionable are EPSS (probability of exploitation in the
//! wild, from FIRST) and CISA KEV (confirmed known-exploited). This module
//! composites those into a per-vulnerability and per-host risk so a subnet sorts by
//! *fix this first*.
//!
//! Data delivery is hybrid (D-NNN): the small, fast-moving feeds (KEV, EPSS) are
//! cached locally so scoring works offline and is testable; CVE matching queries
//! the NVD API on demand. All feeds are public-domain / freely licensed — no
//! C-001-style entanglement. This module covers the scoring engine and the KEV/EPSS
//! ingestion; NVD matching and scan wiring follow.

use crate::error::{Error, Result};
use std::collections::{HashMap, HashSet};

const KEV_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_API: &str = "https://api.first.org/data/v1/epss";
const NVD_API: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const NVD_CPE_API: &str = "https://services.nvd.nist.gov/rest/json/cpes/2.0";

/// One vulnerability affecting a service, with the three triage signals.
#[derive(Debug, Clone, PartialEq)]
pub struct Vuln {
    pub cve_id: String,
    /// CVSS base score (0–10), if known.
    pub cvss: Option<f32>,
    /// EPSS probability of exploitation in the next 30 days (0–1), if known.
    pub epss: Option<f32>,
    /// Listed in the CISA Known Exploited Vulnerabilities catalogue.
    pub kev: bool,
}

/// Coarse triage band for display and sorting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskBand {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl RiskBand {
    pub fn as_str(self) -> &'static str {
        match self {
            RiskBand::Critical => "critical",
            RiskBand::High => "high",
            RiskBand::Medium => "medium",
            RiskBand::Low => "low",
            RiskBand::Informational => "info",
        }
    }
}

/// A single comparable risk number (higher = fix first). Known-exploitation
/// dominates, then EPSS, then CVSS — so a KEV-listed vuln always outranks a
/// high-CVSS / low-EPSS one (C-002, F-015 acceptance).
pub fn risk_score(v: &Vuln) -> f32 {
    let mut score = 0.0;
    if v.kev {
        score += 1000.0; // confirmed exploited — dominates everything else
    }
    if let Some(epss) = v.epss {
        score += epss.clamp(0.0, 1.0) * 100.0; // 0–100
    }
    if let Some(cvss) = v.cvss {
        score += cvss.clamp(0.0, 10.0); // 0–10, the tiebreaker
    }
    score
}

/// The triage band for a vulnerability, exploitation-weighted.
pub fn band(v: &Vuln) -> RiskBand {
    if v.kev {
        return RiskBand::Critical; // known-exploited is always top priority
    }
    let epss = v.epss.unwrap_or(0.0);
    let cvss = v.cvss.unwrap_or(0.0);
    if epss >= 0.5 || cvss >= 9.0 {
        RiskBand::High
    } else if epss >= 0.1 || cvss >= 7.0 {
        RiskBand::Medium
    } else if epss > 0.0 || cvss > 0.0 {
        RiskBand::Low
    } else {
        RiskBand::Informational
    }
}

/// A host's risk is driven by its most urgent vulnerability (the one to fix first).
pub fn host_risk(vulns: &[Vuln]) -> f32 {
    vulns.iter().map(risk_score).fold(0.0, f32::max)
}

// ---- CISA KEV catalogue ---------------------------------------------------

/// The set of CVE IDs CISA lists as known-exploited.
#[derive(Debug, Clone, Default)]
pub struct KevCatalog {
    ids: HashSet<String>,
}

impl KevCatalog {
    /// Parse the catalogue from its published JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        let value: serde_json::Value = serde_json::from_str(json)?;
        let ids = value
            .get("vulnerabilities")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.get("cveID").and_then(|c| c.as_str()).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self { ids })
    }

    /// Fetch the live catalogue from CISA.
    pub fn fetch() -> Result<Self> {
        Self::from_json(&fetch_kev_json()?)
    }

    pub fn contains(&self, cve_id: &str) -> bool {
        self.ids.contains(cve_id)
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }
}

/// Fetch the raw CISA KEV JSON (for caching to disk).
pub fn fetch_kev_json() -> Result<String> {
    http_get(KEV_URL)
}

// ---- EPSS scores ----------------------------------------------------------

/// Parse FIRST's EPSS API response (`/data/v1/epss?cve=…`) into CVE → probability.
pub fn parse_epss(json: &str) -> Result<HashMap<String, f32>> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    let mut scores = HashMap::new();
    if let Some(data) = value.get("data").and_then(|d| d.as_array()) {
        for entry in data {
            if let (Some(cve), Some(epss)) = (
                entry.get("cve").and_then(|c| c.as_str()),
                entry.get("epss").and_then(|e| e.as_str()).and_then(|s| s.parse::<f32>().ok()),
            ) {
                scores.insert(cve.to_string(), epss);
            }
        }
    }
    Ok(scores)
}

/// Fetch EPSS scores for the given CVE IDs from FIRST.
pub fn fetch_epss(cves: &[String]) -> Result<HashMap<String, f32>> {
    if cves.is_empty() {
        return Ok(HashMap::new());
    }
    let url = format!("{EPSS_API}?cve={}", cves.join(","));
    parse_epss(&http_get(&url)?)
}

// ---- NVD CVE matching -----------------------------------------------------

/// A CVE matched to a product, with its CVSS base score where NVD provides one.
#[derive(Debug, Clone, PartialEq)]
pub struct CveRef {
    pub id: String,
    pub cvss: Option<f32>,
}

/// Parse an NVD 2.0 API response into CVE references.
pub fn parse_nvd(json: &str) -> Result<Vec<CveRef>> {
    let value: serde_json::Value = serde_json::from_str(json)?;
    let mut refs = Vec::new();
    if let Some(items) = value.get("vulnerabilities").and_then(|v| v.as_array()) {
        for item in items {
            let Some(cve) = item.get("cve") else { continue };
            let Some(id) = cve.get("id").and_then(|i| i.as_str()) else { continue };
            refs.push(CveRef { id: id.to_string(), cvss: nvd_base_score(cve.get("metrics")) });
        }
    }
    Ok(refs)
}

/// Pull a CVSS base score from an NVD `metrics` object, preferring newer versions.
fn nvd_base_score(metrics: Option<&serde_json::Value>) -> Option<f32> {
    let metrics = metrics?;
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        let score = metrics
            .get(key)
            .and_then(|a| a.as_array())
            .and_then(|a| a.first())
            .and_then(|e| e.get("cvssData"))
            .and_then(|d| d.get("baseScore"))
            .and_then(|s| s.as_f64());
        if let Some(score) = score {
            return Some(score as f32);
        }
    }
    None
}

/// Match a detected product (and version, if known) to CVEs via NVD.
///
/// Uses **CPE applicability matching**, not keyword search: NVD's keyword search is
/// full-text over descriptions and cannot match a product/version reliably, whereas
/// a CPE `virtualMatchString` returns exactly the CVEs whose applicability ranges
/// cover that version. The product is first resolved to its CPE vendor/product via
/// the NVD CPE API; an unresolved product yields no matches (rather than broad,
/// misleading keyword hits).
pub fn fetch_nvd(product: &str, version: Option<&str>) -> Result<Vec<CveRef>> {
    let Some((vendor, prod)) = resolve_cpe(product)? else {
        return Ok(Vec::new());
    };
    let ver = version.filter(|v| !v.is_empty()).unwrap_or("*");
    let cpe = format!("cpe:2.3:a:{vendor}:{prod}:{ver}:*:*:*:*:*:*:*");
    let url = format!("{NVD_API}?virtualMatchString={}&resultsPerPage=50", encode(&cpe));
    parse_nvd(&http_get(&url)?)
}

/// Resolve a product name to its NVD CPE (vendor, product) via the CPE API.
fn resolve_cpe(product: &str) -> Result<Option<(String, String)>> {
    let url = format!("{NVD_CPE_API}?keywordSearch={}&resultsPerPage=50", encode(product));
    Ok(parse_cpe(&http_get(&url)?, product))
}

/// Parse an NVD CPE API response, picking the (vendor, product) whose product part
/// matches the detected name (falling back to the first application CPE).
pub fn parse_cpe(json: &str, product: &str) -> Option<(String, String)> {
    let value: serde_json::Value = serde_json::from_str(json).ok()?;
    let target = product.to_lowercase();
    let mut fallback = None;
    for item in value.get("products")?.as_array()? {
        let Some(name) = item.get("cpe").and_then(|c| c.get("cpeName")).and_then(|n| n.as_str())
        else {
            continue;
        };
        // cpe:2.3:<part>:<vendor>:<product>:<version>:...
        let parts: Vec<&str> = name.split(':').collect();
        if parts.len() > 5 && parts[2] == "a" {
            let pair = (parts[3].to_string(), parts[4].to_string());
            if parts[4].eq_ignore_ascii_case(&target) {
                return Some(pair);
            }
            fallback.get_or_insert(pair);
        }
    }
    fallback
}

/// Assess a detected service: match it to CVEs (NVD), then enrich each with EPSS
/// and the KEV flag, yielding scored [`Vuln`]s. `kev` is the cached catalogue.
pub fn assess(product: &str, version: Option<&str>, kev: &KevCatalog) -> Result<Vec<Vuln>> {
    let cves = fetch_nvd(product, version)?;
    if cves.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<String> = cves.iter().map(|c| c.id.clone()).collect();
    let epss = fetch_epss(&ids).unwrap_or_default(); // best-effort enrichment
    Ok(cves
        .into_iter()
        .map(|c| Vuln {
            epss: epss.get(&c.id).copied(),
            kev: kev.contains(&c.id),
            cvss: c.cvss,
            cve_id: c.id,
        })
        .collect())
}

/// Minimal percent-encoding for query keywords (spaces and a few reserved chars).
fn encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            ' ' => "%20".to_string(),
            '&' => "%26".to_string(),
            '+' => "%2B".to_string(),
            '#' => "%23".to_string(),
            other => other.to_string(),
        })
        .collect()
}

// ---- HTTP -----------------------------------------------------------------

/// Minimal blocking GET used by the feed fetchers.
fn http_get(url: &str) -> Result<String> {
    ureq::get(url)
        .call()
        .map_err(|e| Error::Feed(e.to_string()))?
        .into_string()
        .map_err(|e| Error::Feed(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vuln(cvss: Option<f32>, epss: Option<f32>, kev: bool) -> Vuln {
        Vuln { cve_id: "CVE-0000-0000".to_string(), cvss, epss, kev }
    }

    #[test]
    fn kev_outranks_high_cvss_low_epss() {
        let kev_listed = vuln(Some(5.0), Some(0.01), true);
        let scary_looking = vuln(Some(9.8), Some(0.01), false); // high CVSS, not exploited
        assert!(risk_score(&kev_listed) > risk_score(&scary_looking),
                "known-exploited must sort first (C-002)");
        assert_eq!(band(&kev_listed), RiskBand::Critical);
        assert_eq!(band(&scary_looking), RiskBand::High);
    }

    #[test]
    fn high_epss_outranks_high_cvss() {
        let likely = vuln(Some(6.0), Some(0.9), false);
        let severe = vuln(Some(9.0), Some(0.02), false);
        assert!(risk_score(&likely) > risk_score(&severe));
    }

    #[test]
    fn host_risk_is_its_worst_vuln() {
        let vulns =
            vec![vuln(Some(4.0), Some(0.01), false), vuln(Some(5.0), Some(0.02), true)];
        assert_eq!(host_risk(&vulns), risk_score(&vulns[1]));
    }

    #[test]
    fn kev_catalogue_parses() {
        let json = r#"{"title":"KEV","count":2,"vulnerabilities":[
            {"cveID":"CVE-2021-44228","vendorProject":"Apache"},
            {"cveID":"CVE-2023-1234","vendorProject":"Foo"}]}"#;
        let kev = KevCatalog::from_json(json).unwrap();
        assert_eq!(kev.len(), 2);
        assert!(kev.contains("CVE-2021-44228"));
        assert!(!kev.contains("CVE-2000-0000"));
    }

    #[test]
    fn nvd_response_parses_with_cvss_preference() {
        let json = r#"{"vulnerabilities":[
            {"cve":{"id":"CVE-2019-9511","metrics":{
                "cvssMetricV31":[{"cvssData":{"baseScore":7.5}}],
                "cvssMetricV2":[{"cvssData":{"baseScore":5.0}}]}}},
            {"cve":{"id":"CVE-2020-0001","metrics":{
                "cvssMetricV2":[{"cvssData":{"baseScore":4.3}}]}}},
            {"cve":{"id":"CVE-2021-0002"}}]}"#;
        let refs = parse_nvd(json).unwrap();
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0].cvss, Some(7.5)); // prefers v3.1 over v2
        assert_eq!(refs[1].cvss, Some(4.3)); // falls back to v2
        assert_eq!(refs[2].cvss, None); // no metrics
    }

    #[test]
    fn cpe_response_resolves_vendor_product() {
        let json = r#"{"products":[
            {"cpe":{"cpeName":"cpe:2.3:a:f5:nginx_amp:1.0:*:*:*:*:*:*:*"}},
            {"cpe":{"cpeName":"cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"}}]}"#;
        // Exact product match wins over the earlier near-match.
        assert_eq!(parse_cpe(json, "nginx"), Some(("nginx".to_string(), "nginx".to_string())));
        // Unknown product → first application CPE as a fallback.
        assert_eq!(parse_cpe(json, "zzz"), Some(("f5".to_string(), "nginx_amp".to_string())));
    }

    #[test]
    fn epss_response_parses() {
        let json = r#"{"status":"OK","data":[
            {"cve":"CVE-2021-44228","epss":"0.97560","percentile":"0.99"},
            {"cve":"CVE-2023-1234","epss":"0.00042","percentile":"0.10"}]}"#;
        let scores = parse_epss(json).unwrap();
        assert!((scores["CVE-2021-44228"] - 0.9756).abs() < 1e-4);
        assert!((scores["CVE-2023-1234"] - 0.00042).abs() < 1e-5);
    }
}
