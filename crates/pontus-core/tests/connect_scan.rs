//! Real-socket tests of the stateful deep pass (F-002): connect-scan a loopback
//! listener and confirm the open port and its banner. Unprivileged — this is the
//! path `scan_hosts` falls back to without `CAP_NET_RAW`, and the one we can
//! exercise without raw sockets.

use pontus_core::ScanConfig;
use pontus_core::scan::stateful;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::time::Duration;

fn cfg(ports: Vec<u16>) -> ScanConfig {
    ScanConfig {
        ports,
        sweep_wait: Duration::from_millis(100),
        connect_timeout: Duration::from_millis(500),
        banner_wait: Duration::from_millis(500),
    }
}

/// Spawn a loopback listener that writes `banner` to each connection. Returns the
/// bound port. The listener thread runs for the lifetime of the test process.
fn spawn_banner_listener(banner: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let _ = s.write_all(banner);
        }
    });
    port
}

#[tokio::test]
async fn connect_scan_finds_open_port_and_grabs_banner() {
    let port = spawn_banner_listener(b"SSH-2.0-PontusTest\r\n");

    let result = stateful::connect_scan(IpAddr::V4(Ipv4Addr::LOCALHOST), &[port], &cfg(vec![port])).await;

    assert_eq!(result.open.len(), 1);
    assert_eq!(result.open[0].port, port);
    assert_eq!(result.open[0].proto, "tcp");
    assert_eq!(result.open[0].banner.as_deref(), Some("SSH-2.0-PontusTest"));
}

#[tokio::test]
async fn connect_scan_omits_closed_ports() {
    // Bind then immediately drop a listener to obtain a port nothing listens on.
    let closed_port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };

    let result = stateful::connect_scan(IpAddr::V4(Ipv4Addr::LOCALHOST), &[closed_port], &cfg(vec![closed_port])).await;
    assert!(result.open.is_empty(), "a refused connection is not an open port");
}

#[tokio::test]
async fn connect_scan_mixes_open_and_closed() {
    let open_port = spawn_banner_listener(b"hello\n");
    let closed_port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };

    let result = stateful::connect_scan(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        &[open_port, closed_port],
        &cfg(vec![open_port, closed_port]),
    )
    .await;

    assert_eq!(result.open.len(), 1);
    assert_eq!(result.open[0].port, open_port);
}

#[tokio::test]
async fn scan_hosts_with_no_targets_returns_nothing() {
    // Empty target list must short-circuit without touching a raw socket, so this
    // passes even where CAP_NET_RAW is unavailable.
    let result = pontus_core::scan_hosts(&[], &cfg(vec![80, 443])).await.unwrap();
    assert!(result.is_empty());
}
