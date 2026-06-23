//! End-to-end drift detection (F-014): write two scans into a real store, read the
//! observations back out (exercising the JSON (de)serialisation and the SQL join),
//! and diff them. This is the path `pontus-cli diff` drives.

use pontus_core::{HostStatus, IdentitySignals, ObservationState, PortObservation, PortRef, Store, diff_observations};

fn tcp(port: u16) -> PortRef {
    PortRef { proto: "tcp".to_string(), port }
}

fn state(ports: &[u16]) -> ObservationState {
    ObservationState {
        up: true,
        open_ports: ports
            .iter()
            .map(|&port| PortObservation { port, proto: "tcp".to_string(), service: None, version: None })
            .collect(),
        os_guess: None,
    }
}

fn sig(mac: &str, ip: &str) -> IdentitySignals {
    IdentitySignals {
        mac: Some(mac.to_string()),
        ip: Some(ip.parse().unwrap()),
        ..Default::default()
    }
}

#[test]
fn opened_and_closed_ports_surface_as_drift() {
    let store = Store::open_in_memory().unwrap();
    let mac = "aa:bb:cc:dd:ee:01";

    let s1 = store.begin_scan("net", "s", None).unwrap();
    store.record(&sig(mac, "192.168.1.5"), s1, &state(&[22, 80])).unwrap();
    store.finish_scan(s1).unwrap();

    let s2 = store.begin_scan("net", "s", None).unwrap();
    store.record(&sig(mac, "192.168.1.5"), s2, &state(&[80, 443])).unwrap();
    store.finish_scan(s2).unwrap();

    let diff = diff_observations(
        &store.observations_for_scan(s1).unwrap(),
        &store.observations_for_scan(s2).unwrap(),
    );

    assert_eq!(diff.len(), 1);
    assert_eq!(diff[0].status, HostStatus::Changed);
    assert_eq!(diff[0].opened, vec![tcp(443)]);
    assert_eq!(diff[0].closed, vec![tcp(22)]);
}

#[test]
fn ip_move_on_a_stable_asset_is_reported_as_a_move_not_a_new_host() {
    let store = Store::open_in_memory().unwrap();
    let mac = "aa:bb:cc:dd:ee:02";

    let s1 = store.begin_scan("net", "s", None).unwrap();
    store.record(&sig(mac, "192.168.1.10"), s1, &state(&[22])).unwrap();
    store.finish_scan(s1).unwrap();

    let s2 = store.begin_scan("net", "s", None).unwrap();
    store.record(&sig(mac, "192.168.1.20"), s2, &state(&[22])).unwrap();
    store.finish_scan(s2).unwrap();

    let diff = diff_observations(
        &store.observations_for_scan(s1).unwrap(),
        &store.observations_for_scan(s2).unwrap(),
    );

    assert_eq!(diff.len(), 1, "one asset, not two");
    assert_eq!(diff[0].status, HostStatus::Changed);
    assert_eq!(diff[0].moved_from.as_deref(), Some("192.168.1.10"));
}

#[test]
fn new_and_vanished_hosts_are_distinguished() {
    let store = Store::open_in_memory().unwrap();

    let s1 = store.begin_scan("net", "s", None).unwrap();
    store.record(&sig("aa:aa:aa:aa:aa:01", "192.168.1.1"), s1, &state(&[80])).unwrap();
    store.finish_scan(s1).unwrap();

    let s2 = store.begin_scan("net", "s", None).unwrap();
    store.record(&sig("aa:aa:aa:aa:aa:02", "192.168.1.2"), s2, &state(&[22])).unwrap();
    store.finish_scan(s2).unwrap();

    let diff = diff_observations(
        &store.observations_for_scan(s1).unwrap(),
        &store.observations_for_scan(s2).unwrap(),
    );

    let vanished = diff.iter().filter(|d| d.status == HostStatus::Vanished).count();
    let new = diff.iter().filter(|d| d.status == HostStatus::New).count();
    assert_eq!((vanished, new), (1, 1));
}
