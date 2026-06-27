//! The asset/observation domain types (F-003).

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// The signals observed for a host on a single scan, from which a durable asset
/// identity is resolved. The resolution *order* is fixed — MAC, then stable host
/// key / TLS cert fingerprint, then hostname, then IP — because IP is not a stable
/// identifier (C-003, F-004). A bare IP is the weakest, last-resort signal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentitySignals {
    /// Link-layer address (local segment only). Strongest signal.
    pub mac: Option<String>,
    /// Stable host key or TLS certificate fingerprint.
    pub host_key: Option<String>,
    /// Resolved hostname.
    pub hostname: Option<String>,
    /// Address the host was seen on this scan. Weakest signal; never the anchor
    /// when anything stronger is present.
    pub ip: Option<IpAddr>,
}

impl IdentitySignals {
    /// Convenience constructor for the common "only an IP" case.
    pub fn from_ip(ip: IpAddr) -> Self {
        Self { ip: Some(ip), ..Self::default() }
    }
}

/// Which class of signal a stored asset is currently anchored on. Persisted as the
/// `identity_kind` column; the ordering of the variants *is* the priority order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IdentityKind {
    /// Last-resort anchor. Reassigned by DHCP/cloud churn (C-003).
    Ip,
    Hostname,
    HostKey,
    Mac,
}

impl IdentityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            IdentityKind::Mac => "mac",
            IdentityKind::HostKey => "host_key",
            IdentityKind::Hostname => "hostname",
            IdentityKind::Ip => "ip",
        }
    }
}

/// One host's state as captured by a single scan — the payload of an observation.
/// Stored as JSON so the shape can grow (services, OS guess, findings) without a
/// schema migration on the append-only `observations` table.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservationState {
    /// Whether the host responded at all during discovery.
    pub up: bool,
    pub open_ports: Vec<PortObservation>,
    pub os_guess: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortObservation {
    pub port: u16,
    /// "tcp" or "udp".
    pub proto: String,
    pub service: Option<String>,
    pub version: Option<String>,
    /// TLS inspection summary, when the deep pass ran on this port (F-016).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsObservation>,
    /// Web technologies identified on this port, when the deep pass ran (F-017).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tech: Vec<TechObservation>,
}

/// A compact, storable summary of a TLS endpoint inspection (F-016). The full
/// detail is available from `pontus-cli tls`; this is what an observation keeps.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsObservation {
    /// Supported protocol version labels, e.g. ["TLS 1.2", "TLS 1.3"].
    pub protocols: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub weak_ciphers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_subject: Option<String>,
    /// Certificate expiry as a Unix timestamp.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_not_after: Option<i64>,
    #[serde(default)]
    pub self_signed: bool,
    /// Human-readable weakness descriptions (expired, deprecated protocol, …).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<String>,
}

/// One web technology identified on a port (F-017).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TechObservation {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub category: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_observation_json_without_deep_fields_still_deserializes() {
        // An observation stored before F-016/F-017 has no tls/tech keys.
        let json = r#"{"port":443,"proto":"tcp","service":"https","version":null}"#;
        let p: PortObservation = serde_json::from_str(json).unwrap();
        assert_eq!(p.port, 443);
        assert!(p.tls.is_none());
        assert!(p.tech.is_empty());
    }

    #[test]
    fn deep_fields_round_trip_and_stay_compact_when_empty() {
        // Empty tls/tech are skipped, so the JSON matches the pre-F-016 shape.
        let bare = PortObservation { port: 80, proto: "tcp".into(), ..Default::default() };
        let json = serde_json::to_string(&bare).unwrap();
        assert!(!json.contains("tls"), "empty tls is skipped: {json}");
        assert!(!json.contains("tech"), "empty tech is skipped: {json}");

        // A populated one round-trips.
        let rich = PortObservation {
            port: 443,
            proto: "tcp".into(),
            service: Some("https".into()),
            version: None,
            tls: Some(TlsObservation {
                protocols: vec!["TLS 1.2".into(), "TLS 1.3".into()],
                weak_ciphers: vec!["RSA-3DES-EDE-CBC-SHA".into()],
                cert_subject: Some("CN=example.com".into()),
                cert_not_after: Some(1_700_000_000),
                self_signed: false,
                findings: vec!["certificate has expired".into()],
            }),
            tech: vec![TechObservation { name: "nginx".into(), version: Some("1.18.0".into()), category: "server".into() }],
        };
        let back: PortObservation = serde_json::from_str(&serde_json::to_string(&rich).unwrap()).unwrap();
        assert_eq!(rich, back);
    }
}
