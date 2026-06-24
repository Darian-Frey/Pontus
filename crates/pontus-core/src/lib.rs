//! `pontus-core` — the headless engine.
//!
//! Both `pontus-cli` and (later) the Qt GUI are clients of this crate; no
//! GUI- or CLI-specific logic lives here (D-001). The architectural centre of
//! gravity is the asset inventory, not the scan: durable [`model::IdentitySignals`]
//! resolve to durable assets, and a scan writes append-only observations against
//! them (D-007).

pub mod diff;
pub mod discovery;
pub mod error;
pub mod identity;
pub mod model;
mod raw;
pub mod rdns;
pub mod scan;
pub mod scope;
pub mod store;
pub mod traceroute;

pub use diff::{HostDiff, HostStatus, PortRef, diff_observations};
pub use discovery::{DiscoveredHost, DiscoveryError, Method};
pub use scan::{HostPorts, OpenPort, ScanConfig, scan_hosts};
pub use error::{Error, Result};
pub use model::{IdentityKind, IdentitySignals, ObservationState, PortObservation};
pub use scope::{Scope, ScopeError};
pub use store::{AssetObservation, AssetSummary, Edge, HostObservation, ScanRef, Store};

#[cfg(test)]
mod tests;
