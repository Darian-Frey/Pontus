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
    fn epss_response_parses() {
        let json = r#"{"status":"OK","data":[
            {"cve":"CVE-2021-44228","epss":"0.97560","percentile":"0.99"},
            {"cve":"CVE-2023-1234","epss":"0.00042","percentile":"0.10"}]}"#;
        let scores = parse_epss(json).unwrap();
        assert!((scores["CVE-2021-44228"] - 0.9756).abs() < 1e-4);
        assert!((scores["CVE-2023-1234"] - 0.00042).abs() < 1e-5);
    }
}
