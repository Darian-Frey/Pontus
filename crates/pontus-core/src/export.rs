//! Scan export (F-023): a structured, pipeline-friendly view of one scan, with
//! JSON-native, SARIF 2.1 and CSV serialisers. JSON output is the differentiator
//! Nmap lacks; SARIF lets findings flow into CI/code-scanning dashboards; CSV is
//! the spreadsheet/quick-grep escape hatch. HTML/PDF reports are a later slice.
//!
//! The report is assembled from the store's existing read surface (observations,
//! risk-ranked vulns, plugin findings, packages) joined by `asset_id`, so it stays
//! a thin projection of the data model rather than a parallel one.

use crate::store::Store;
use crate::Result;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeMap;

/// One scan, flattened for export: metadata plus a row per host.
#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub tool: &'static str,
    pub tool_version: &'static str,
    pub scan: ScanMeta,
    pub hosts: Vec<HostReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanMeta {
    pub id: i64,
    pub targets: String,
    pub started_at: String,
    pub finished_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HostReport {
    pub asset_id: i64,
    pub identity_kind: String,
    pub identity_value: String,
    pub ip: Option<String>,
    pub up: bool,
    pub os: Option<String>,
    pub ports: Vec<PortReport>,
    pub vulns: Vec<VulnReport>,
    pub findings: Vec<FindingReport>,
    pub packages: Vec<PackageReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PortReport {
    pub port: u16,
    pub proto: String,
    pub service: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VulnReport {
    pub cve_id: String,
    pub cvss: Option<f32>,
    pub epss: Option<f32>,
    pub kev: bool,
    pub band: String,
    pub version_matched: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingReport {
    pub plugin: String,
    pub title: String,
    pub severity: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackageReport {
    pub name: String,
    pub version: String,
}

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Assemble the export report for a scan from the store.
pub fn report(store: &Store, scan_id: i64) -> Result<ScanReport> {
    let scan = store
        .scan(scan_id)?
        .ok_or_else(|| crate::error::Error::NotFound(format!("scan {scan_id}")))?;
    let meta = ScanMeta {
        id: scan.id,
        targets: scan.targets,
        started_at: scan.started_at,
        finished_at: scan.finished_at,
    };

    // Group vulns / findings / packages by asset so each host carries its own.
    let mut vulns: BTreeMap<i64, Vec<VulnReport>> = BTreeMap::new();
    for h in store.risk_ranked(scan_id)? {
        vulns.insert(
            h.asset_id,
            h.vulns
                .into_iter()
                .map(|v| VulnReport {
                    cve_id: v.cve_id,
                    cvss: v.cvss,
                    epss: v.epss,
                    kev: v.kev,
                    band: v.band,
                    version_matched: v.version_matched,
                })
                .collect(),
        );
    }
    let mut findings: BTreeMap<i64, Vec<FindingReport>> = BTreeMap::new();
    for f in store.findings_for_scan(scan_id)? {
        findings.entry(f.asset_id).or_default().push(FindingReport {
            plugin: f.plugin,
            title: f.title,
            severity: f.severity,
            description: f.description,
        });
    }
    let mut packages: BTreeMap<i64, Vec<PackageReport>> = BTreeMap::new();
    for p in store.packages_for_scan(scan_id)? {
        packages
            .entry(p.asset_id)
            .or_default()
            .push(PackageReport { name: p.name, version: p.version });
    }

    let hosts = store
        .observations_for_scan(scan_id)?
        .into_iter()
        .map(|o| HostReport {
            ports: o
                .state
                .open_ports
                .iter()
                .map(|p| PortReport {
                    port: p.port,
                    proto: p.proto.clone(),
                    service: p.service.clone(),
                    version: p.version.clone(),
                })
                .collect(),
            vulns: vulns.remove(&o.asset_id).unwrap_or_default(),
            findings: findings.remove(&o.asset_id).unwrap_or_default(),
            packages: packages.remove(&o.asset_id).unwrap_or_default(),
            up: o.state.up,
            os: o.state.os_guess,
            asset_id: o.asset_id,
            identity_kind: o.identity_kind,
            identity_value: o.identity_value,
            ip: Some(o.ip),
        })
        .collect();

    Ok(ScanReport { tool: "pontus", tool_version: TOOL_VERSION, scan: meta, hosts })
}

/// Pretty JSON — the native, lossless export.
pub fn to_json(report: &ScanReport) -> String {
    serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
}

/// CSV with one row per host (the inventory view). Spreadsheet/grep-friendly.
pub fn to_csv(report: &ScanReport) -> String {
    let mut out = String::from(
        "asset_id,identity_kind,identity_value,ip,up,os,open_ports,vuln_count,top_band,finding_count\n",
    );
    for h in &report.hosts {
        let ports = h
            .ports
            .iter()
            .map(|p| format!("{}/{}", p.proto, p.port))
            .collect::<Vec<_>>()
            .join(" ");
        let top_band = h.vulns.first().map(|v| v.band.as_str()).unwrap_or("");
        let row = [
            h.asset_id.to_string(),
            h.identity_kind.clone(),
            h.identity_value.clone(),
            h.ip.clone().unwrap_or_default(),
            if h.up { "up".into() } else { "down".into() },
            h.os.clone().unwrap_or_default(),
            ports,
            h.vulns.len().to_string(),
            top_band.to_string(),
            h.findings.len().to_string(),
        ];
        out.push_str(&row.iter().map(|f| csv_field(f)).collect::<Vec<_>>().join(","));
        out.push('\n');
    }
    out
}

/// Quote a CSV field if it contains a comma, quote or newline (RFC 4180).
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// SARIF 2.1.0 — each vulnerability and plugin finding becomes a result, so the
/// scan can flow into CI / code-scanning dashboards. The host (IP/identity) is the
/// result location.
pub fn to_sarif(report: &ScanReport) -> String {
    let mut rules: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut results: Vec<serde_json::Value> = Vec::new();

    for host in &report.hosts {
        let loc = host.ip.clone().unwrap_or_else(|| host.identity_value.clone());

        for v in &host.vulns {
            rules.entry(v.cve_id.clone()).or_insert_with(|| {
                json!({
                    "id": v.cve_id,
                    "name": v.cve_id,
                    "shortDescription": { "text": format!("{} (CVSS {})", v.cve_id,
                        v.cvss.map(|c| c.to_string()).unwrap_or_else(|| "n/a".into())) },
                    "helpUri": format!("https://nvd.nist.gov/vuln/detail/{}", v.cve_id),
                    "properties": { "kev": v.kev, "epss": v.epss, "band": v.band }
                })
            });
            let extra = if v.kev { " [KEV]" } else { "" };
            results.push(sarif_result(
                &v.cve_id,
                band_level(&v.band),
                &format!(
                    "{} on {}{} — CVSS {}, EPSS {}{}",
                    v.cve_id,
                    loc,
                    if v.version_matched { "" } else { " (product-wide match)" },
                    v.cvss.map(|c| c.to_string()).unwrap_or_else(|| "n/a".into()),
                    v.epss.map(|e| format!("{:.1}%", e * 100.0)).unwrap_or_else(|| "n/a".into()),
                    extra,
                ),
                &loc,
            ));
        }

        for f in &host.findings {
            let rule_id = format!("{}/{}", f.plugin, slug(&f.title));
            rules.entry(rule_id.clone()).or_insert_with(|| {
                json!({
                    "id": rule_id,
                    "name": f.title,
                    "shortDescription": { "text": f.title },
                    "properties": { "plugin": f.plugin }
                })
            });
            let text = if f.description.is_empty() {
                format!("{} on {}", f.title, loc)
            } else {
                format!("{} on {} — {}", f.title, loc, f.description)
            };
            results.push(sarif_result(&rule_id, severity_level(&f.severity), &text, &loc));
        }
    }

    let doc = json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": { "driver": {
                "name": "Pontus",
                "informationUri": "https://github.com/Darian-Frey/Pontus",
                "version": report.tool_version,
                "rules": rules.into_values().collect::<Vec<_>>(),
            }},
            "results": results,
        }]
    });
    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

fn sarif_result(rule_id: &str, level: &str, text: &str, host: &str) -> serde_json::Value {
    json!({
        "ruleId": rule_id,
        "level": level,
        "message": { "text": text },
        "locations": [{
            "physicalLocation": { "artifactLocation": { "uri": host } },
            "logicalLocations": [{ "name": host, "kind": "resource" }]
        }]
    })
}

/// SARIF level for a risk band.
fn band_level(band: &str) -> &'static str {
    match band {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

/// SARIF level for a plugin-finding severity.
fn severity_level(sev: &str) -> &'static str {
    match sev {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

/// A conservative ruleId slug from a finding title.
fn slug(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{IdentitySignals, ObservationState, PortObservation};

    fn seed() -> (Store, i64) {
        let store = Store::open_in_memory().unwrap();
        let s = store.begin_scan("192.168.1.0/24", "192.168.1.0/24", Some("op")).unwrap();
        let sig = IdentitySignals {
            mac: Some("aa:bb:cc:dd:ee:ff".into()),
            ip: Some("192.168.1.10".parse().unwrap()),
            ..Default::default()
        };
        let state = ObservationState {
            up: true,
            open_ports: vec![PortObservation {
                port: 80,
                proto: "tcp".into(),
                service: Some("http".into()),
                ..Default::default()
            }],
            os_guess: Some("Linux/Unix".into()),
        };
        let a = store.record(&sig, s, &state).unwrap();
        let vuln = crate::Vuln {
            cve_id: "CVE-2023-44487".into(),
            cvss: Some(7.5),
            epss: Some(0.9),
            kev: true,
            version_matched: true,
        };
        store.record_vuln(s, a, 80, &vuln).unwrap();
        let finding = crate::StoredFinding {
            asset_id: a,
            plugin: "http-header-audit".into(),
            title: "HSTS not set".into(),
            severity: "low".into(),
            description: "No Strict-Transport-Security header.".into(),
            ..Default::default()
        };
        store.record_finding(s, &finding).unwrap();
        store.record_package(s, a, "nginx", "1.18.0").unwrap();
        store.finish_scan(s).unwrap();
        (store, s)
    }

    #[test]
    fn report_joins_everything_onto_the_host() {
        let (store, s) = seed();
        let r = report(&store, s).unwrap();
        assert_eq!(r.hosts.len(), 1);
        let h = &r.hosts[0];
        assert_eq!(h.ip.as_deref(), Some("192.168.1.10"));
        assert_eq!(h.ports.len(), 1);
        assert_eq!(h.vulns.len(), 1);
        assert_eq!(h.findings.len(), 1);
        assert_eq!(h.packages.len(), 1);
        assert_eq!(h.os.as_deref(), Some("Linux/Unix"));
    }

    #[test]
    fn json_round_trips_and_carries_the_tool_name() {
        let (store, s) = seed();
        let j = to_json(&report(&store, s).unwrap());
        let v: serde_json::Value = serde_json::from_str(&j).unwrap();
        assert_eq!(v["tool"], "pontus");
        assert_eq!(v["hosts"][0]["vulns"][0]["cve_id"], "CVE-2023-44487");
    }

    #[test]
    fn csv_has_a_header_and_one_row_per_host() {
        let (store, s) = seed();
        let csv = to_csv(&report(&store, s).unwrap());
        let lines: Vec<&str> = csv.lines().collect();
        assert!(lines[0].starts_with("asset_id,identity_kind"));
        assert_eq!(lines.len(), 2, "header + one host");
        assert!(lines[1].contains("192.168.1.10"));
        assert!(lines[1].contains("tcp/80"));
    }

    #[test]
    fn sarif_has_required_shape_and_maps_levels() {
        let (store, s) = seed();
        let sarif = to_sarif(&report(&store, s).unwrap());
        let v: serde_json::Value = serde_json::from_str(&sarif).unwrap();
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "Pontus");
        let results = v["runs"][0]["results"].as_array().unwrap();
        // One CVE result (error: KEV→critical band) + one finding (note: low).
        assert_eq!(results.len(), 2);
        assert!(results.iter().any(|r| r["ruleId"] == "CVE-2023-44487" && r["level"] == "error"));
        assert!(results.iter().any(|r| r["level"] == "note")); // the low finding
        // Every result carries a location.
        assert!(results.iter().all(|r| r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "192.168.1.10"));
        // Rules are de-duplicated and present.
        assert!(!v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().is_empty());
    }
}
