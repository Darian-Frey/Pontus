//! Unit tests for the Phase 1 invariants that are exercisable without a network
//! or `CAP_NET_RAW`: scope enforcement (F-007), append-only observations (D-007),
//! and the headline identity-resolution case — a forced IP change resolving to
//! the same asset (F-004).

use crate::model::{IdentitySignals, ObservationState};
use crate::scope::{Scope, ScopeError};
use crate::store::Store;
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn sig(mac: Option<&str>, ip_s: &str) -> IdentitySignals {
    IdentitySignals {
        mac: mac.map(str::to_string),
        ip: Some(ip(ip_s)),
        ..Default::default()
    }
}

// ---- Scope (F-007) --------------------------------------------------------

#[test]
fn scope_refuses_out_of_scope_target() {
    let scope = Scope::parse(["192.168.1.0/24"]).unwrap();
    assert!(scope.ensure(ip("192.168.1.50")).is_ok());
    match scope.ensure(ip("10.0.0.1")) {
        Err(ScopeError::OutOfScope(a)) => assert_eq!(a, ip("10.0.0.1")),
        other => panic!("expected OutOfScope, got {other:?}"),
    }
}

#[test]
fn scope_cannot_be_empty() {
    assert!(matches!(Scope::parse(Vec::<String>::new()), Err(ScopeError::Empty)));
    assert!(matches!(Scope::new(vec![]), Err(ScopeError::Empty)));
}

#[test]
fn scope_handles_ipv6_and_bare_hosts() {
    let scope = Scope::parse(["2001:db8::/32", "203.0.113.7"]).unwrap();
    assert!(scope.contains(ip("2001:db8::1")));
    assert!(scope.contains(ip("203.0.113.7")));
    assert!(!scope.contains(ip("203.0.113.8")));
    assert!(!scope.contains(ip("2001:db9::1")));
}

#[test]
fn scope_rejects_garbage() {
    assert!(matches!(Scope::parse(["not-an-ip"]), Err(ScopeError::Invalid(_))));
}

// ---- Identity resolution (F-004, C-003) -----------------------------------

#[test]
fn forced_ip_change_resolves_to_same_asset() {
    let store = Store::open_in_memory().unwrap();

    // Scan 1: host at .10 with a MAC.
    let s1 = store.begin_scan("192.168.1.0/24", "192.168.1.0/24", None).unwrap();
    let a1 = store
        .record(&sig(Some("aa:bb:cc:dd:ee:ff"), "192.168.1.10"), s1, &ObservationState { up: true, ..Default::default() })
        .unwrap();
    store.finish_scan(s1).unwrap();

    // Scan 2: same MAC, new address (forced DHCP lease change).
    let s2 = store.begin_scan("192.168.1.0/24", "192.168.1.0/24", None).unwrap();
    let a2 = store
        .record(&sig(Some("aa:bb:cc:dd:ee:ff"), "192.168.1.20"), s2, &ObservationState { up: true, ..Default::default() })
        .unwrap();
    store.finish_scan(s2).unwrap();

    assert_eq!(a1, a2, "same MAC on a new IP must resolve to the same asset");
    assert_eq!(store.asset_count().unwrap(), 1, "no duplicate asset row");
    assert_eq!(store.observation_count().unwrap(), 2, "two observation sets");

    // The asset now tracks the latest address.
    let last_ip: String = store
        .conn()
        .query_row("SELECT last_ip FROM assets WHERE id = ?1", [a1], |r| r.get(0))
        .unwrap();
    assert_eq!(last_ip, "192.168.1.20");
}

#[test]
fn distinct_macs_are_distinct_assets() {
    let store = Store::open_in_memory().unwrap();
    let s = store.begin_scan("192.168.1.0/24", "192.168.1.0/24", None).unwrap();
    store.record(&sig(Some("aa:aa:aa:aa:aa:aa"), "192.168.1.10"), s, &ObservationState::default()).unwrap();
    store.record(&sig(Some("bb:bb:bb:bb:bb:bb"), "192.168.1.11"), s, &ObservationState::default()).unwrap();
    assert_eq!(store.asset_count().unwrap(), 2);
}

#[test]
fn ip_only_host_promoted_when_mac_appears() {
    let store = Store::open_in_memory().unwrap();
    let s1 = store.begin_scan("t", "s", None).unwrap();
    // First seen with only an IP — anchored on IP.
    let a1 = store.record(&sig(None, "192.168.1.30"), s1, &ObservationState::default()).unwrap();
    // Later the same IP yields a MAC — should fold into the same asset and promote.
    let s2 = store.begin_scan("t", "s", None).unwrap();
    let a2 = store.record(&sig(Some("aa:bb:cc:11:22:33"), "192.168.1.30"), s2, &ObservationState::default()).unwrap();
    assert_eq!(a1, a2);
    assert_eq!(store.asset_count().unwrap(), 1);
    let kind: String = store
        .conn()
        .query_row("SELECT identity_kind FROM assets WHERE id = ?1", [a1], |r| r.get(0))
        .unwrap();
    assert_eq!(kind, "mac", "asset should be promoted from ip- to mac-anchored");
}

#[test]
fn record_without_any_signal_is_rejected() {
    let store = Store::open_in_memory().unwrap();
    let s = store.begin_scan("t", "s", None).unwrap();
    let err = store.record(&IdentitySignals::default(), s, &ObservationState::default());
    assert!(matches!(err, Err(crate::Error::NoIdentitySignal)));
}

// ---- Append-only observations (D-007) -------------------------------------

#[test]
fn baseline_round_trips() {
    let store = Store::open_in_memory().unwrap();
    assert_eq!(store.baseline().unwrap(), None, "no baseline initially");
    let s1 = store.begin_scan("t", "s", None).unwrap();
    let s2 = store.begin_scan("t", "s", None).unwrap();
    store.set_baseline(s1).unwrap();
    assert_eq!(store.baseline().unwrap(), Some(s1));
    // Re-designating replaces, not duplicates.
    store.set_baseline(s2).unwrap();
    assert_eq!(store.baseline().unwrap(), Some(s2));
}

#[test]
fn observations_are_append_only() {
    let store = Store::open_in_memory().unwrap();
    let s = store.begin_scan("t", "s", None).unwrap();
    store.record(&sig(Some("aa:bb:cc:dd:ee:01"), "192.168.1.40"), s, &ObservationState::default()).unwrap();

    let update = store.conn().execute("UPDATE observations SET ip = '0.0.0.0'", []);
    assert!(update.is_err(), "UPDATE on observations must be rejected by trigger");

    let delete = store.conn().execute("DELETE FROM observations", []);
    assert!(delete.is_err(), "DELETE on observations must be rejected by trigger");

    assert_eq!(store.observation_count().unwrap(), 1);
}
