//! The stable plugin data contract (F-020): what a plugin is *given* and what it
//! *returns*. Every type here is serde-serialisable so the same shape crosses
//! every runner's boundary — a Lua table now, a WASM/JSON payload or a Python
//! dict later — without a per-runner schema.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How serious a finding is. Ordered least → most severe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// One structured result produced by a plugin. `plugin` is stamped by the host
/// (a plugin need not — and should not — name itself), so plugins typically return
/// findings with just a title/severity/description and optional metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Producing plugin's name; filled in by the host after the plugin returns.
    #[serde(default)]
    pub plugin: String,
    /// Short headline, e.g. "Telnet exposed".
    pub title: String,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub description: String,
    /// Free-form structured extras (e.g. `port = "23"`), preserved verbatim.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

/// What a plugin runs against: one host and its observed ports/services. This is
/// the read-only view the host hands to a plugin; plugins never mutate it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Target {
    pub ip: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub ports: Vec<TargetPort>,
}

/// One open port on the target, with whatever service/version detection found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetPort {
    pub port: u16,
    pub proto: String,
    #[serde(default)]
    pub service: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

impl Target {
    /// Convenience constructor for a host with no ports yet.
    pub fn new(ip: impl Into<String>) -> Self {
        Target { ip: ip.into(), hostname: None, ports: Vec::new() }
    }

    /// Builder-style: add an open port.
    pub fn with_port(mut self, port: u16, proto: impl Into<String>) -> Self {
        self.ports.push(TargetPort {
            port,
            proto: proto.into(),
            service: None,
            version: None,
        });
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_and_serialises_lowercase() {
        assert!(Severity::Critical > Severity::Info);
        assert_eq!(serde_json::to_string(&Severity::High).unwrap(), "\"high\"");
        assert_eq!(
            serde_json::from_str::<Severity>("\"medium\"").unwrap(),
            Severity::Medium
        );
    }

    #[test]
    fn finding_defaults_fill_optional_fields() {
        // A minimal plugin-shaped finding (no plugin/severity/metadata) round-trips.
        let f: Finding = serde_json::from_str(r#"{"title":"x"}"#).unwrap();
        assert_eq!(f.title, "x");
        assert_eq!(f.severity, Severity::Info);
        assert!(f.plugin.is_empty());
        assert!(f.metadata.is_empty());
    }
}
