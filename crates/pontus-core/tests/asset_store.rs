//! End-to-end tests of the asset/observation store through the public API
//! (F-003, F-004, D-007). These exercise the same surface the CLI and GUI use,
//! and need no privilege or network.

use pontus_core::{IdentitySignals, ObservationState, Store};

fn sig(mac: Option<&str>, ip: &str) -> IdentitySignals {
    IdentitySignals {
        mac: mac.map(str::to_string),
        ip: Some(ip.parse().unwrap()),
        ..Default::default()
    }
}

fn up() -> ObservationState {
    ObservationState { up: true, ..Default::default() }
}

#[test]
fn two_scans_of_a_host_make_one_asset_and_two_observations() {
    let store = Store::open_in_memory().unwrap();

    let s1 = store.begin_scan("192.168.1.0/24", "192.168.1.0/24", Some("op")).unwrap();
    let a1 = store.record(&sig(Some("aa:bb:cc:dd:ee:ff"), "192.168.1.10"), s1, &up()).unwrap();
    store.finish_scan(s1).unwrap();

    let s2 = store.begin_scan("192.168.1.0/24", "192.168.1.0/24", Some("op")).unwrap();
    let a2 = store.record(&sig(Some("aa:bb:cc:dd:ee:ff"), "192.168.1.10"), s2, &up()).unwrap();
    store.finish_scan(s2).unwrap();

    assert_eq!(a1, a2);
    assert_eq!(store.asset_count().unwrap(), 1);
    assert_eq!(store.observation_count().unwrap(), 2);
}

#[test]
fn forced_ip_change_resolves_to_the_same_asset() {
    let store = Store::open_in_memory().unwrap();
    let mac = Some("de:ad:be:ef:00:01");

    let s1 = store.begin_scan("n", "s", None).unwrap();
    let a1 = store.record(&sig(mac, "192.168.1.10"), s1, &up()).unwrap();

    let s2 = store.begin_scan("n", "s", None).unwrap();
    let a2 = store.record(&sig(mac, "192.168.1.250"), s2, &up()).unwrap();

    assert_eq!(a1, a2, "same MAC on a new IP must be the same asset (F-004)");
    assert_eq!(store.asset_count().unwrap(), 1);
}

#[test]
fn icmp_only_sighting_after_arp_resolves_to_the_same_asset() {
    // The identity-merge fix (BUG-012). Scan 1 sees the host via ARP, so it carries
    // a MAC and anchors a MAC-identified asset. Scan 2 sees the *same* host via ICMP
    // only (ARP didn't fire) — no MAC, just the IP. The MAC-less sighting must attach
    // to the existing asset, not fork a second, IP-anchored one.
    let store = Store::open_in_memory().unwrap();

    let s1 = store.begin_scan("n", "s", None).unwrap();
    let a1 = store.record(&sig(Some("aa:bb:cc:dd:ee:ff"), "192.168.1.10"), s1, &up()).unwrap();
    store.finish_scan(s1).unwrap();

    let s2 = store.begin_scan("n", "s", None).unwrap();
    let a2 = store.record(&sig(None, "192.168.1.10"), s2, &up()).unwrap();
    store.finish_scan(s2).unwrap();

    assert_eq!(a1, a2, "a MAC-less sighting at a known host's IP must not fork an asset");
    assert_eq!(store.asset_count().unwrap(), 1, "no duplicate IP-anchored asset (BUG-012)");
    assert_eq!(store.observation_count().unwrap(), 2);
}

#[test]
fn a_distinct_mac_at_a_known_ip_stays_its_own_asset() {
    // The recycle guard the merge must not break: a *different* host seen by ARP at
    // an address a previous host used is unambiguous (the MAC anchors it), so it is
    // never folded into the prior tenant (C-003).
    let store = Store::open_in_memory().unwrap();

    let s1 = store.begin_scan("n", "s", None).unwrap();
    let a1 = store.record(&sig(Some("aa:aa:aa:aa:aa:aa"), "192.168.1.10"), s1, &up()).unwrap();
    store.finish_scan(s1).unwrap();

    let s2 = store.begin_scan("n", "s", None).unwrap();
    let a2 = store.record(&sig(Some("bb:bb:bb:bb:bb:bb"), "192.168.1.10"), s2, &up()).unwrap();
    store.finish_scan(s2).unwrap();

    assert_ne!(a1, a2, "a new MAC at a recycled address is its own host");
    assert_eq!(store.asset_count().unwrap(), 2);
}

#[test]
fn a_bare_ip_resolves_to_the_most_recent_tenant_of_that_address() {
    // When a lease is recycled and we later get a MAC-less sighting, it should land
    // on whichever host most recently held the address, not the departed one.
    let store = Store::open_in_memory().unwrap();

    // Old tenant, then a new tenant takes the same IP (both seen via ARP).
    let s1 = store.begin_scan("n", "s", None).unwrap();
    let old = store.record(&sig(Some("aa:aa:aa:aa:aa:aa"), "192.168.1.10"), s1, &up()).unwrap();
    store.finish_scan(s1).unwrap();

    let s2 = store.begin_scan("n", "s", None).unwrap();
    let new = store.record(&sig(Some("bb:bb:bb:bb:bb:bb"), "192.168.1.10"), s2, &up()).unwrap();
    store.finish_scan(s2).unwrap();

    // A later ICMP-only sighting of that address resolves to the current tenant.
    let s3 = store.begin_scan("n", "s", None).unwrap();
    let seen = store.record(&sig(None, "192.168.1.10"), s3, &up()).unwrap();
    store.finish_scan(s3).unwrap();

    assert_eq!(seen, new, "a bare IP follows the most recent tenant");
    assert_ne!(seen, old);
    assert_eq!(store.asset_count().unwrap(), 2, "no third asset spawned");
}

#[test]
fn observations_cannot_be_mutated_through_the_store_connection() {
    let store = Store::open_in_memory().unwrap();
    let s = store.begin_scan("n", "s", None).unwrap();
    store.record(&sig(Some("aa:aa:aa:aa:aa:aa"), "10.0.0.1"), s, &up()).unwrap();

    assert!(
        store.conn().execute("UPDATE observations SET ip = '0.0.0.0'", []).is_err(),
        "append-only trigger must reject UPDATE (D-007)"
    );
    assert!(
        store.conn().execute("DELETE FROM observations", []).is_err(),
        "append-only trigger must reject DELETE (D-007)"
    );
    assert_eq!(store.observation_count().unwrap(), 1);
}

#[test]
fn audit_record_persists_targets_scope_and_operator() {
    let store = Store::open_in_memory().unwrap();
    let s = store.begin_scan("192.168.1.0/24", "192.168.1.0/24", Some("shane")).unwrap();
    store.finish_scan(s).unwrap();

    let scan = store.scan(s).unwrap().expect("scan exists");
    assert_eq!(scan.targets, "192.168.1.0/24");
    assert!(scan.finished_at.is_some(), "finish_scan stamps a completion time");
}

#[test]
fn risk_ranked_dedupes_a_cve_recorded_on_multiple_ports() {
    use pontus_core::Vuln;

    let store = Store::open_in_memory().unwrap();
    let s = store.begin_scan("n", "s", None).unwrap();
    let a = store.record(&sig(Some("aa:bb:cc:dd:ee:ff"), "192.168.1.10"), s, &up()).unwrap();

    // The same CVE on 80 and 443 (e.g. a web server on both), plus a second CVE.
    let shared = Vuln {
        cve_id: "CVE-2023-44487".into(),
        cvss: Some(7.5),
        epss: Some(1.0),
        kev: true,
        version_matched: true,
    };
    let other = Vuln {
        cve_id: "CVE-2009-3555".into(),
        cvss: Some(9.8),
        epss: Some(0.8),
        kev: false,
        version_matched: true,
    };
    store.record_vuln(s, a, 80, &shared).unwrap();
    store.record_vuln(s, a, 443, &shared).unwrap();
    store.record_vuln(s, a, 80, &other).unwrap();
    store.finish_scan(s).unwrap();

    let ranked = store.risk_ranked(s).unwrap();
    assert_eq!(ranked.len(), 1);
    let host = &ranked[0];
    // Two unique CVEs, not three — the shared one collapses across ports.
    assert_eq!(host.vulns.len(), 2, "CVE deduped across ports");
    assert_eq!(host.vulns.iter().filter(|v| v.cve_id == "CVE-2023-44487").count(), 1);
    // KEV dominates, so the deduped KEV CVE remains the top finding.
    assert_eq!(host.vulns[0].cve_id, "CVE-2023-44487");
}

#[test]
fn risk_ranked_carries_version_matched_flag() {
    use pontus_core::Vuln;

    let store = Store::open_in_memory().unwrap();
    let s = store.begin_scan("n", "s", None).unwrap();
    let a = store.record(&sig(Some("aa:bb:cc:dd:ee:ff"), "192.168.1.10"), s, &up()).unwrap();

    // A product-wide (version-less) match and a precise one.
    let wide = Vuln { cve_id: "CVE-2009-3555".into(), cvss: Some(9.8), epss: Some(0.9), kev: false, version_matched: false };
    let exact = Vuln { cve_id: "CVE-2023-44487".into(), cvss: Some(7.5), epss: Some(1.0), kev: true, version_matched: true };
    store.record_vuln(s, a, 80, &wide).unwrap();
    store.record_vuln(s, a, 443, &exact).unwrap();
    store.finish_scan(s).unwrap();

    let host = &store.risk_ranked(s).unwrap()[0];
    let find = |id: &str| host.vulns.iter().find(|v| v.cve_id == id).unwrap();
    assert!(!find("CVE-2009-3555").version_matched, "version-less flagged");
    assert!(find("CVE-2023-44487").version_matched, "precise flagged");
}
