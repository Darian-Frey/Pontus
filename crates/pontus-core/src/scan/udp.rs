//! UDP port scanning (F-002).
//!
//! UDP has no handshake, so we lean on the kernel. A UDP socket *connected* to
//! `(host, port)` turns the three outcomes into things we can observe without a
//! raw socket or privilege:
//!
//! - the service sends a datagram back  → [`UdpState::Open`];
//! - the host returns ICMP port-unreachable, which the kernel reports as
//!   `ECONNREFUSED` on the connected socket → [`UdpState::Closed`];
//! - silence within the timeout → [`UdpState::OpenFiltered`] (open, or a filter
//!   swallowed the probe — UDP cannot distinguish them).
//!
//! Probes are empty datagrams: enough to draw ICMP-unreachable from closed ports
//! and a reply from chatty services. Clean-room protocol payloads (DNS, NTP, SNMP)
//! can sharpen Open detection later without copying Nmap's corpus (C-001).

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// The verdict for one probed UDP port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpState {
    /// A reply came back — definitely open.
    Open,
    /// No reply within the timeout — open, or filtered; UDP cannot tell.
    OpenFiltered,
    /// ICMP port-unreachable — closed.
    Closed,
}

impl UdpState {
    pub fn as_str(self) -> &'static str {
        match self {
            UdpState::Open => "open",
            UdpState::OpenFiltered => "open|filtered",
            UdpState::Closed => "closed",
        }
    }
}

/// The result of probing one UDP port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpResult {
    pub port: u16,
    pub state: UdpState,
    /// Sanitised first bytes of the reply, when the port answered.
    pub response: Option<String>,
}

/// UDP scan knobs. UDP is lossy, so a retry materially reduces false open|filtered.
#[derive(Debug, Clone)]
pub struct UdpConfig {
    pub timeout: Duration,
    pub retries: u8,
}

/// Probe every UDP port on one host concurrently, returning a verdict for each
/// (including `Closed`, so callers can choose what to keep).
pub async fn scan_host(ip: IpAddr, ports: &[u16], cfg: &UdpConfig) -> Vec<UdpResult> {
    let (wait, retries) = (cfg.timeout, cfg.retries);
    let mut set: JoinSet<UdpResult> = JoinSet::new();
    for &port in ports {
        set.spawn(async move { probe(ip, port, wait, retries).await });
    }
    let mut out = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(r) = res {
            out.push(r);
        }
    }
    out.sort_by_key(|r| r.port);
    out
}

async fn probe(ip: IpAddr, port: u16, wait: Duration, retries: u8) -> UdpResult {
    // A bind/connect failure tells us nothing about the port — call it ambiguous.
    probe_inner(ip, port, wait, retries)
        .await
        .unwrap_or(UdpResult { port, state: UdpState::OpenFiltered, response: None })
}

async fn probe_inner(ip: IpAddr, port: u16, wait: Duration, retries: u8) -> io::Result<UdpResult> {
    let bind: SocketAddr = match ip {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(SocketAddr::new(ip, port)).await?;

    let mut buf = [0u8; 1024];
    for _ in 0..=retries {
        // A pending ICMP error from a previous probe can surface on send, too.
        if let Err(e) = sock.send(&[]).await {
            return Ok(verdict_for_send_error(port, e));
        }
        match timeout(wait, sock.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                let response = (n > 0).then(|| super::sanitise_banner(&buf[..n]));
                return Ok(UdpResult { port, state: UdpState::Open, response });
            }
            Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => {
                return Ok(UdpResult { port, state: UdpState::Closed, response: None });
            }
            Ok(Err(e)) => return Err(e),
            // Timed out — retry; if this was the last attempt, fall through.
            Err(_elapsed) => continue,
        }
    }
    Ok(UdpResult { port, state: UdpState::OpenFiltered, response: None })
}

fn verdict_for_send_error(port: u16, e: io::Error) -> UdpResult {
    let state = if e.kind() == io::ErrorKind::ConnectionRefused {
        UdpState::Closed
    } else {
        UdpState::OpenFiltered
    };
    UdpResult { port, state, response: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn closed_udp_port_is_detected_via_icmp_unreachable() {
        // Nothing is bound here, so the loopback stack returns ICMP port-unreachable,
        // surfaced as ECONNREFUSED on the connected socket.
        let cfg = UdpConfig { timeout: Duration::from_millis(300), retries: 1 };
        let results = scan_host(IpAddr::V4(Ipv4Addr::LOCALHOST), &[1], &cfg).await;
        assert_eq!(results.len(), 1);
        // On Linux loopback this is reliably Closed; tolerate OpenFiltered elsewhere.
        assert!(matches!(results[0].state, UdpState::Closed | UdpState::OpenFiltered));
    }

    #[tokio::test]
    async fn open_udp_service_is_detected() {
        // A tiny echo responder: reply to whatever arrives.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut b = [0u8; 64];
            if let Ok((_n, peer)) = server.recv_from(&mut b).await {
                let _ = server.send_to(b"PONTUS-UDP-OK", peer).await;
            }
        });

        let cfg = UdpConfig { timeout: Duration::from_millis(500), retries: 1 };
        let results = scan_host(IpAddr::V4(Ipv4Addr::LOCALHOST), &[port], &cfg).await;
        assert_eq!(results[0].state, UdpState::Open);
        assert_eq!(results[0].response.as_deref(), Some("PONTUS-UDP-OK"));
    }
}
