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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortObservation {
    pub port: u16,
    /// "tcp" or "udp".
    pub proto: String,
    pub service: Option<String>,
    pub version: Option<String>,
}
