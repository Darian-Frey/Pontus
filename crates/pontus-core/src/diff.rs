//! Scan diffing (F-014, first cut).
//!
//! Drift falls straight out of the data model: because observations are keyed to a
//! durable `asset_id` (D-007), comparing two scans is a join on asset id, not a
//! fuzzy match across point-in-time outputs. This module is the headless comparison
//! the CLI `diff` renders and the GUI will reuse.

use crate::store::HostObservation;
use std::collections::{BTreeMap, BTreeSet};

/// What happened to a host between the two scans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostStatus {
    /// Seen in the later scan but not the earlier one.
    New,
    /// Seen in the earlier scan but not the later one.
    Vanished,
    /// Seen in both, with a port or address change.
    Changed,
    /// Seen in both, identical.
    Unchanged,
}

/// The change to one host across two scans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDiff {
    pub asset_id: i64,
    pub identity_kind: String,
    pub identity_value: String,
    /// The host's address in the later scan (or the earlier one if it vanished).
    pub ip: String,
    pub status: HostStatus,
    /// Ports open in the later scan but not the earlier one.
    pub opened: Vec<u16>,
    /// Ports open in the earlier scan but not the later one.
    pub closed: Vec<u16>,
    /// The earlier address, if the host moved (same asset, new IP — the C-003 case).
    pub moved_from: Option<String>,
}

/// Compare the observations of an earlier scan (`from`) and a later one (`to`),
/// producing one [`HostDiff`] per asset seen in either, sorted by asset id.
pub fn diff_observations(from: &[HostObservation], to: &[HostObservation]) -> Vec<HostDiff> {
    let from_map: BTreeMap<i64, &HostObservation> = from.iter().map(|h| (h.asset_id, h)).collect();
    let to_map: BTreeMap<i64, &HostObservation> = to.iter().map(|h| (h.asset_id, h)).collect();

    let ids: BTreeSet<i64> = from_map.keys().chain(to_map.keys()).copied().collect();

    let mut diffs = Vec::with_capacity(ids.len());
    for id in ids {
        let diff = match (from_map.get(&id), to_map.get(&id)) {
            (None, Some(t)) => HostDiff {
                asset_id: id,
                identity_kind: t.identity_kind.clone(),
                identity_value: t.identity_value.clone(),
                ip: t.ip.clone(),
                status: HostStatus::New,
                opened: open_ports(t),
                closed: Vec::new(),
                moved_from: None,
            },
            (Some(f), None) => HostDiff {
                asset_id: id,
                identity_kind: f.identity_kind.clone(),
                identity_value: f.identity_value.clone(),
                ip: f.ip.clone(),
                status: HostStatus::Vanished,
                opened: Vec::new(),
                closed: open_ports(f),
                moved_from: None,
            },
            (Some(f), Some(t)) => {
                let before: BTreeSet<u16> = open_ports(f).into_iter().collect();
                let after: BTreeSet<u16> = open_ports(t).into_iter().collect();
                let opened: Vec<u16> = after.difference(&before).copied().collect();
                let closed: Vec<u16> = before.difference(&after).copied().collect();
                let moved_from = (f.ip != t.ip).then(|| f.ip.clone());
                let status = if opened.is_empty() && closed.is_empty() && moved_from.is_none() {
                    HostStatus::Unchanged
                } else {
                    HostStatus::Changed
                };
                HostDiff {
                    asset_id: id,
                    identity_kind: t.identity_kind.clone(),
                    identity_value: t.identity_value.clone(),
                    ip: t.ip.clone(),
                    status,
                    opened,
                    closed,
                    moved_from,
                }
            }
            (None, None) => unreachable!("id came from one of the two maps"),
        };
        diffs.push(diff);
    }
    diffs
}

fn open_ports(h: &HostObservation) -> Vec<u16> {
    h.state.open_ports.iter().map(|p| p.port).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ObservationState, PortObservation};

    fn obs(asset_id: i64, ip: &str, ports: &[u16]) -> HostObservation {
        HostObservation {
            asset_id,
            identity_kind: "mac".to_string(),
            identity_value: format!("mac-{asset_id}"),
            ip: ip.to_string(),
            state: ObservationState {
                up: true,
                open_ports: ports
                    .iter()
                    .map(|&port| PortObservation { port, proto: "tcp".to_string(), service: None, version: None })
                    .collect(),
                os_guess: None,
            },
        }
    }

    #[test]
    fn detects_new_and_vanished_hosts() {
        let from = vec![obs(1, "192.168.1.1", &[80])];
        let to = vec![obs(2, "192.168.1.2", &[22])];
        let d = diff_observations(&from, &to);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].status, HostStatus::Vanished);
        assert_eq!(d[0].closed, vec![80]);
        assert_eq!(d[1].status, HostStatus::New);
        assert_eq!(d[1].opened, vec![22]);
    }

    #[test]
    fn detects_opened_and_closed_ports() {
        let from = vec![obs(1, "192.168.1.1", &[22, 80])];
        let to = vec![obs(1, "192.168.1.1", &[80, 443])];
        let d = diff_observations(&from, &to);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].status, HostStatus::Changed);
        assert_eq!(d[0].opened, vec![443]);
        assert_eq!(d[0].closed, vec![22]);
        assert!(d[0].moved_from.is_none());
    }

    #[test]
    fn detects_ip_move_with_stable_asset() {
        let from = vec![obs(1, "192.168.1.10", &[22])];
        let to = vec![obs(1, "192.168.1.20", &[22])];
        let d = diff_observations(&from, &to);
        assert_eq!(d[0].status, HostStatus::Changed);
        assert_eq!(d[0].moved_from.as_deref(), Some("192.168.1.10"));
        assert!(d[0].opened.is_empty() && d[0].closed.is_empty());
    }

    #[test]
    fn identical_host_is_unchanged() {
        let from = vec![obs(1, "192.168.1.1", &[80, 443])];
        let to = vec![obs(1, "192.168.1.1", &[443, 80])];
        let d = diff_observations(&from, &to);
        assert_eq!(d[0].status, HostStatus::Unchanged);
    }
}
