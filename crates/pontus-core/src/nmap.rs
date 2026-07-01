//! Nmap XML import (F-025) — a migration bridge that brings an existing
//! `nmap -oX` run into the asset store as durable assets + observations (D-007),
//! so a user with a pile of Nmap scans can start from their real inventory. This
//! is a *parse and record*, not a scan: no packets are sent, so scope enforcement
//! (a live-scanning safety, F-007) does not apply.
//!
//! Nmap host addresses map onto the identity hierarchy (MAC → hostname → IP,
//! C-003); open ports and their service/version become the observation's ports;
//! the best `osmatch` becomes the OS guess. Reuses `roxmltree` (already the
//! Nmap-detector dependency); nothing is vendored (D-006/C-001).

use crate::error::{Error, Result};
use crate::model::{IdentitySignals, ObservationState, PortObservation};
use crate::store::Store;

/// One host parsed from an Nmap XML `<host>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmapHost {
    pub ip: Option<String>,
    pub mac: Option<String>,
    pub hostname: Option<String>,
    pub up: bool,
    pub ports: Vec<NmapPort>,
    pub os: Option<String>,
}

/// An open port from an Nmap `<port>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NmapPort {
    pub port: u16,
    pub proto: String,
    pub service: Option<String>,
    pub version: Option<String>,
}

/// What an import recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportSummary {
    pub scan_id: i64,
    pub hosts: usize,
    pub observations: usize,
}

/// Parse Nmap XML into hosts. Pure — no store, no I/O.
pub fn parse(xml: &str) -> Result<Vec<NmapHost>> {
    // Nmap XML carries a `<!DOCTYPE nmaprun>`; roxmltree rejects DTDs by default.
    let opts = roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() };
    let doc = roxmltree::Document::parse_with_options(xml, opts).map_err(|e| Error::Parse(e.to_string()))?;
    let root = doc.root_element();
    if !root.has_tag_name("nmaprun") {
        return Err(Error::Parse("not an Nmap XML document (no <nmaprun>)".into()));
    }

    let mut hosts = Vec::new();
    for host in root.children().filter(|n| n.has_tag_name("host")) {
        let up = host
            .children()
            .find(|n| n.has_tag_name("status"))
            .and_then(|s| s.attribute("state"))
            == Some("up");

        let mut ip = None;
        let mut mac = None;
        for a in host.children().filter(|n| n.has_tag_name("address")) {
            match a.attribute("addrtype") {
                Some("ipv4") | Some("ipv6") => ip = a.attribute("addr").map(str::to_string),
                Some("mac") => mac = a.attribute("addr").map(|m| m.to_ascii_lowercase()),
                _ => {}
            }
        }

        let hostname = host
            .descendants()
            .find(|n| n.has_tag_name("hostname"))
            .and_then(|h| h.attribute("name"))
            .map(str::to_string);

        let mut ports = Vec::new();
        for p in host.descendants().filter(|n| n.has_tag_name("port")) {
            let state = p
                .children()
                .find(|n| n.has_tag_name("state"))
                .and_then(|s| s.attribute("state"))
                .unwrap_or("");
            if !state.starts_with("open") {
                continue; // open / open|filtered only — the inventory-relevant ports
            }
            let Some(port) = p.attribute("portid").and_then(|s| s.parse::<u16>().ok()) else {
                continue;
            };
            let proto = p.attribute("protocol").unwrap_or("tcp").to_string();
            let svc = p.children().find(|n| n.has_tag_name("service"));
            let service = svc.and_then(|s| s.attribute("name")).map(str::to_string);
            let version = svc.and_then(|s| {
                let parts: Vec<&str> = [s.attribute("product"), s.attribute("version")]
                    .into_iter()
                    .flatten()
                    .collect();
                (!parts.is_empty()).then(|| parts.join(" "))
            });
            ports.push(NmapPort { port, proto, service, version });
        }

        // Nmap lists osmatch highest-accuracy first; take the best.
        let os = host
            .descendants()
            .find(|n| n.has_tag_name("osmatch"))
            .and_then(|o| o.attribute("name"))
            .map(str::to_string);

        hosts.push(NmapHost { ip, mac, hostname, up, ports, os });
    }
    Ok(hosts)
}

/// Parse and record an Nmap XML into the store as a scan of observations.
/// `source` labels the scan (e.g. the file name). Only up hosts with an address
/// are imported.
pub fn import(store: &Store, xml: &str, source: &str, operator: Option<&str>) -> Result<ImportSummary> {
    let hosts = parse(xml)?;
    let scan_id = store.begin_scan(source, source, operator)?;

    let mut observations = 0;
    for h in &hosts {
        if !h.up {
            continue;
        }
        let Some(ip) = h.ip.as_ref().and_then(|s| s.parse().ok()) else {
            continue; // need an address to anchor/record the observation
        };
        let sig = IdentitySignals {
            mac: h.mac.clone(),
            hostname: h.hostname.clone(),
            ip: Some(ip),
            ..Default::default()
        };
        let state = ObservationState {
            up: true,
            open_ports: h
                .ports
                .iter()
                .map(|p| PortObservation {
                    port: p.port,
                    proto: p.proto.clone(),
                    service: p.service.clone(),
                    version: p.version.clone(),
                    ..Default::default()
                })
                .collect(),
            os_guess: h.os.clone(),
        };
        store.record(&sig, scan_id, &state)?;
        observations += 1;
    }
    store.finish_scan(scan_id)?;
    Ok(ImportSummary { scan_id, hosts: hosts.len(), observations })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX - 192.168.1.0/24" start="1700000000">
  <host starttime="1700000001">
    <status state="up" reason="arp-response"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme"/>
    <hostnames><hostname name="host.example" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="closed" reason="reset"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.4" accuracy="98"/><osmatch name="Linux 4.x" accuracy="90"/></os>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="192.168.1.11" addrtype="ipv4"/>
  </host>
</nmaprun>"#;

    #[test]
    fn parses_hosts_addresses_ports_and_os() {
        let hosts = parse(SAMPLE).unwrap();
        assert_eq!(hosts.len(), 2);
        let h = &hosts[0];
        assert!(h.up);
        assert_eq!(h.ip.as_deref(), Some("192.168.1.10"));
        assert_eq!(h.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"), "MAC lowercased");
        assert_eq!(h.hostname.as_deref(), Some("host.example"));
        assert_eq!(h.os.as_deref(), Some("Linux 5.4"), "best osmatch");
        // Only the open port is kept, with service + composed version.
        assert_eq!(h.ports.len(), 1);
        assert_eq!(h.ports[0].port, 22);
        assert_eq!(h.ports[0].service.as_deref(), Some("ssh"));
        assert_eq!(h.ports[0].version.as_deref(), Some("OpenSSH 8.9p1"));
        assert!(!hosts[1].up);
    }

    #[test]
    fn accepts_real_nmap_doctype_and_stylesheet() {
        // Real `nmap -oX` output has a DOCTYPE and a stylesheet PI, which a
        // default XML parser rejects.
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="nmap" args="nmap -oX - 127.0.0.1">
  <host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports></host>
</nmaprun>"#;
        let hosts = parse(xml).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].ports[0].port, 80);
    }

    #[test]
    fn rejects_non_nmap_xml() {
        assert!(matches!(parse("<foo/>"), Err(Error::Parse(_))));
        assert!(matches!(parse("not xml at all <"), Err(Error::Parse(_))));
    }

    #[test]
    fn import_records_up_hosts_as_observations() {
        let store = Store::open_in_memory().unwrap();
        let s = import(&store, SAMPLE, "scan.xml", Some("op")).unwrap();
        assert_eq!(s.hosts, 2, "both hosts parsed");
        assert_eq!(s.observations, 1, "only the up host is recorded");
        assert_eq!(store.asset_count().unwrap(), 1);
        // The MAC anchored the asset (C-003); the open port and OS came through.
        let obs = store.observations_for_scan(s.scan_id).unwrap();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].identity_value, "aa:bb:cc:dd:ee:ff");
        assert_eq!(obs[0].state.open_ports.len(), 1);
        assert_eq!(obs[0].state.os_guess.as_deref(), Some("Linux 5.4"));
    }
}
