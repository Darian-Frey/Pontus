//! `pontus-core` — the headless engine.
//!
//! Both `pontus-cli` and (later) the Qt GUI are clients of this crate; no
//! GUI- or CLI-specific logic lives here (D-001). The architectural centre of
//! gravity is the asset inventory, not the scan: durable [`model::IdentitySignals`]
//! resolve to durable assets, and a scan writes append-only observations against
//! them (D-007).

pub mod detect;
pub mod diff;
pub mod discovery;
pub mod error;
pub mod identity;
pub mod intel;
pub mod model;
pub mod netinfo;
pub mod os;
mod raw;
pub mod rdns;
pub mod scan;
pub mod scope;
pub mod store;
pub mod tls;
pub mod traceroute;
pub mod webtech;

pub use detect::{Detector, NativeDetector, NmapDetector, PortProbe, Service};
pub use intel::{CveRef, KevCatalog, RiskBand, Vuln, assess, band, host_risk, risk_score};
pub use diff::{HostDiff, HostStatus, PortRef, diff_observations};
pub use discovery::{DiscoveredHost, DiscoveryError, Method};
pub use scan::{HostPorts, OpenPort, ScanConfig, scan_hosts};
pub use error::{Error, Result};
pub use model::{
    IdentityKind, IdentitySignals, ObservationState, PortObservation, TechObservation,
    TlsObservation,
};
pub use netinfo::{Interface, IfAddr, ListenPort, LocalConfig, local_config};
pub use os::{
    NativeOsDetector, NmapOsDetector, OsCorpus, OsDetector, OsGuess, OsSignals, fingerprint,
};
pub use scope::{Scope, ScopeError};
pub use tls::{CertInfo, Finding, ProtocolVersion, TlsReport, inspect};
pub use webtech::{Category, Tech, WebFingerprint};
pub use store::{
    AssetObservation, AssetSummary, AssetVuln, Edge, HostObservation, HostRisk, RankedVuln,
    ScanRef, Store,
};

#[cfg(test)]
mod tests;
