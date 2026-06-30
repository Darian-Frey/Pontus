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

/// Minimal HTML escaping for text interpolated into the report.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// A self-contained, styled HTML report (inline CSS, no external resources) — for
/// reading and sharing. Asset-centric: a summary, an overview table, then a
/// per-host section with ports, vulnerabilities and findings.
pub fn to_html(report: &ScanReport) -> String {
    let total_vulns: usize = report.hosts.iter().map(|h| h.vulns.len()).sum();
    let total_findings: usize = report.hosts.iter().map(|h| h.findings.len()).sum();
    let up = report.hosts.iter().filter(|h| h.up).count();
    let kev = report
        .hosts
        .iter()
        .flat_map(|h| &h.vulns)
        .filter(|v| v.kev)
        .count();

    let mut s = String::new();
    s.push_str("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n");
    s.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    s.push_str(&format!("<title>Pontus scan report — scan {}</title>\n", report.scan.id));
    s.push_str(STYLE);
    s.push_str("</head>\n<body>\n");

    s.push_str("<h1>Pontus scan report</h1>\n");
    s.push_str(&format!(
        "<p class=\"meta\">Scan #{} · targets <code>{}</code> · started {}{} · {} v{}</p>\n",
        report.scan.id,
        esc(&report.scan.targets),
        esc(&report.scan.started_at),
        report
            .scan
            .finished_at
            .as_deref()
            .map(|f| format!(" → {}", esc(f)))
            .unwrap_or_default(),
        report.tool,
        report.tool_version,
    ));

    // Summary cards.
    s.push_str("<div class=\"cards\">\n");
    for (label, value) in [
        ("Hosts", report.hosts.len()),
        ("Up", up),
        ("Vulnerabilities", total_vulns),
        ("KEV", kev),
        ("Findings", total_findings),
    ] {
        s.push_str(&format!("<div class=\"card\"><div class=\"n\">{value}</div><div class=\"l\">{label}</div></div>\n"));
    }
    s.push_str("</div>\n");

    // Overview table.
    s.push_str("<h2>Inventory</h2>\n<table><thead><tr>");
    for h in ["Host", "Identity", "OS", "Ports", "Vulns", "Findings"] {
        s.push_str(&format!("<th>{h}</th>"));
    }
    s.push_str("</tr></thead><tbody>\n");
    for h in &report.hosts {
        let host = esc(h.ip.as_deref().unwrap_or(&h.identity_value));
        s.push_str(&format!(
            "<tr><td><a href=\"#h{}\">{}</a></td><td>{} {}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            h.asset_id,
            host,
            esc(&h.identity_kind),
            esc(&h.identity_value),
            esc(h.os.as_deref().unwrap_or("-")),
            h.ports.len(),
            h.vulns.len(),
            h.findings.len(),
        ));
    }
    s.push_str("</tbody></table>\n");

    // Per-host detail.
    s.push_str("<h2>Hosts</h2>\n");
    for h in &report.hosts {
        let host = esc(h.ip.as_deref().unwrap_or(&h.identity_value));
        s.push_str(&format!("<section class=\"host\" id=\"h{}\">\n", h.asset_id));
        s.push_str(&format!(
            "<h3>{} <span class=\"sub\">{} {} · {} · OS {}</span></h3>\n",
            host,
            esc(&h.identity_kind),
            esc(&h.identity_value),
            if h.up { "up" } else { "down" },
            esc(h.os.as_deref().unwrap_or("unknown")),
        ));

        if !h.ports.is_empty() {
            s.push_str("<p class=\"ports\"><strong>Open ports:</strong> ");
            let ports: Vec<String> = h
                .ports
                .iter()
                .map(|p| {
                    let svc = p
                        .service
                        .as_deref()
                        .map(|v| format!(" {}", esc(v)))
                        .unwrap_or_default();
                    format!("<code>{}/{}{}</code>", esc(&p.proto), p.port, svc)
                })
                .collect();
            s.push_str(&ports.join(" "));
            s.push_str("</p>\n");
        }

        if !h.vulns.is_empty() {
            s.push_str("<table class=\"vulns\"><thead><tr><th>CVE</th><th>Band</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Match</th></tr></thead><tbody>\n");
            for v in &h.vulns {
                s.push_str(&format!(
                    "<tr class=\"b-{}\"><td><a href=\"https://nvd.nist.gov/vuln/detail/{}\">{}</a></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    esc(&v.band),
                    esc(&v.cve_id),
                    esc(&v.cve_id),
                    esc(&v.band),
                    v.cvss.map(|c| format!("{c:.1}")).unwrap_or_else(|| "-".into()),
                    v.epss.map(|e| format!("{:.1}%", e * 100.0)).unwrap_or_else(|| "-".into()),
                    if v.kev { "● KEV" } else { "" },
                    if v.version_matched { "exact" } else { "product-wide" },
                ));
            }
            s.push_str("</tbody></table>\n");
        }

        if !h.findings.is_empty() {
            s.push_str("<ul class=\"findings\">\n");
            for f in &h.findings {
                s.push_str(&format!(
                    "<li class=\"sev-{}\"><span class=\"badge\">{}</span> <strong>{}</strong> <span class=\"plugin\">{}</span><div class=\"desc\">{}</div></li>\n",
                    esc(&f.severity),
                    esc(&f.severity),
                    esc(&f.title),
                    esc(&f.plugin),
                    esc(&f.description),
                ));
            }
            s.push_str("</ul>\n");
        }
        s.push_str("</section>\n");
    }

    s.push_str("</body></html>\n");
    s
}

const STYLE: &str = r#"<style>
:root{--bg:#0f1115;--fg:#e6e6e6;--mut:#9aa0a6;--card:#1a1d23;--line:#2a2e36;
--crit:#c0392b;--high:#e06a0a;--med:#d4a017;--low:#6b7280}
*{box-sizing:border-box}body{margin:0;padding:2rem;background:var(--bg);color:var(--fg);
font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
h1{font-size:1.5rem;margin:0 0 .25rem}h2{margin:2rem 0 .5rem;border-bottom:1px solid var(--line);padding-bottom:.25rem}
h3{margin:.2rem 0}.meta{color:var(--mut);margin:.25rem 0 1rem}code{background:var(--card);padding:.05rem .3rem;border-radius:3px}
a{color:#6cb6ff;text-decoration:none}a:hover{text-decoration:underline}
.cards{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:.75rem 1.25rem;min-width:6rem}
.card .n{font-size:1.6rem;font-weight:600}.card .l{color:var(--mut);font-size:.8rem;text-transform:uppercase;letter-spacing:.05em}
table{border-collapse:collapse;width:100%;margin:.5rem 0}th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid var(--line)}
th{color:var(--mut);font-weight:600;font-size:.8rem;text-transform:uppercase;letter-spacing:.04em}
.host{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:1rem 1.25rem;margin:1rem 0}
.host .sub{color:var(--mut);font-size:.85rem;font-weight:400}
.b-critical td:first-child a,.b-critical td:nth-child(2){color:var(--crit);font-weight:600}
.b-high td:first-child a,.b-high td:nth-child(2){color:var(--high);font-weight:600}
.b-medium td:first-child a,.b-medium td:nth-child(2){color:var(--med)}
.findings{list-style:none;padding:0}.findings li{padding:.4rem 0;border-bottom:1px solid var(--line)}
.badge{display:inline-block;min-width:4.5rem;text-align:center;padding:.05rem .4rem;border-radius:4px;font-size:.75rem;text-transform:uppercase;background:var(--low);color:#fff}
.sev-critical .badge{background:var(--crit)}.sev-high .badge{background:var(--high)}.sev-medium .badge{background:var(--med)}
.plugin{color:var(--mut);font-size:.8rem}.desc{color:var(--mut);font-size:.85rem;margin-top:.15rem}
</style>
"#;

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
    fn html_is_self_contained_and_escapes() {
        let (store, s) = seed();
        let html = to_html(&report(&store, s).unwrap());
        assert!(html.starts_with("<!doctype html>"));
        assert!(html.contains("<style>") && !html.contains("http-equiv=\"refresh\""));
        assert!(html.contains("Pontus scan report"));
        assert!(html.contains("CVE-2023-44487"));
        assert!(html.contains("192.168.1.10"));
        assert!(html.contains("HSTS not set"));
    }

    #[test]
    fn html_escapes_special_characters_in_findings() {
        let store = Store::open_in_memory().unwrap();
        let sc = store.begin_scan("n", "s", None).unwrap();
        let sig = IdentitySignals { ip: Some("10.0.0.1".parse().unwrap()), ..Default::default() };
        let a = store.record(&sig, sc, &ObservationState { up: true, ..Default::default() }).unwrap();
        store
            .record_finding(
                sc,
                &crate::StoredFinding {
                    asset_id: a,
                    plugin: "p".into(),
                    title: "<script>alert(1)</script>".into(),
                    severity: "low".into(),
                    description: "a & b < c".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        store.finish_scan(sc).unwrap();
        let html = to_html(&report(&store, sc).unwrap());
        assert!(!html.contains("<script>alert(1)</script>"), "title must be escaped");
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("a &amp; b &lt; c"));
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
