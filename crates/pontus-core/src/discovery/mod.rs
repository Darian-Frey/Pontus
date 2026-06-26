//! Host discovery (F-001).
//!
//! Finds live hosts ahead of the scan pipeline. The packet construction/parsing
//! lives in [`packet`] (pure, unit-tested); the async raw-socket senders that use
//! it land alongside it. Raw sockets need `CAP_NET_RAW`; callers that lack it get
//! a clear [`DiscoveryError::Privilege`] rather than a silent failure.

pub mod arp;
pub mod iface;
pub mod icmp;
pub mod packet;

use pnet::util::MacAddr;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use thiserror::Error;

/// How a host was found — recorded so the engine can prefer MAC-bearing methods
/// (ARP/NDP) that strengthen identity resolution (F-004).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Arp,
    IcmpEcho,
    TcpConnect,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Arp => "arp",
            Method::IcmpEcho => "icmp",
            Method::TcpConnect => "tcp",
        }
    }
}

/// A host confirmed alive by discovery. `mac` is present only for link-local
/// methods (ARP today, NDP next), and is the strongest identity signal we can get.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredHost {
    pub ip: IpAddr,
    pub mac: Option<MacAddr>,
    pub method: Method,
    /// IPv4 echo-reply TTL, when the host answered ICMP — an OS fingerprint
    /// signal for hosts with no open ports (F-013, IMP-006). `None` for
    /// ARP-only or IPv6 hits.
    pub ttl: Option<u8>,
}

impl DiscoveredHost {
    pub fn new(ip: IpAddr, mac: Option<MacAddr>, method: Method) -> Self {
        Self { ip, mac, method, ttl: None }
    }
}

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("raw-socket discovery needs CAP_NET_RAW (or root): {0}")]
    Privilege(String),
    #[error("no usable network interface for target {0}")]
    NoInterface(IpAddr),
    #[error("discovery I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl DiscoveryError {
    /// True if discovery failed purely for want of `CAP_NET_RAW`, so a caller can
    /// fall back to an unprivileged method rather than abort.
    pub fn is_privilege(&self) -> bool {
        matches!(self, DiscoveryError::Privilege(_))
    }
}

/// Classify a raw-socket/datalink error: `EPERM`/`EACCES` means we lack
/// `CAP_NET_RAW`; anything else is a genuine I/O failure.
pub(crate) fn priv_or_io(e: io::Error) -> DiscoveryError {
    if e.kind() == io::ErrorKind::PermissionDenied {
        DiscoveryError::Privilege(e.to_string())
    } else {
        DiscoveryError::Io(e)
    }
}

/// Discover which of `targets` are alive (F-001).
///
/// On-segment IPv4 hosts are swept with ARP first (yielding a MAC), then every
/// IPv4 target is pinged with ICMP and every IPv6 target with ICMPv6 (D-004);
/// the results are merged so an ARP hit's MAC wins over a bare ICMP hit. `wait`
/// bounds how long each method listens for replies.
///
/// Returns [`DiscoveryError::Privilege`] if raw sockets are unavailable — callers
/// without `CAP_NET_RAW` should fall back to an unprivileged method.
pub async fn discover(targets: &[IpAddr], wait: Duration) -> Result<Vec<DiscoveredHost>, DiscoveryError> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for t in targets {
        match t {
            IpAddr::V4(a) => v4.push(*a),
            IpAddr::V6(a) => v6.push(*a),
        }
    }

    let mut all = Vec::new();

    if !v4.is_empty() {
        // ARP the on-segment targets. We resolve the interface from the first
        // local target and ARP everything in that interface's subnet; off-segment
        // (routed) targets are left to ICMP. Multi-interface fan-out is a later
        // refinement (single primary interface for now).
        if let Some(local) = v4.iter().copied().find_map(iface::local_v4_iface_for) {
            let arp_targets: Vec<Ipv4Addr> =
                v4.iter().copied().filter(|a| local.network.contains(*a)).collect();
            let (ifc, src_ip, mac) = (local.iface.clone(), local.src_ip, local.mac);
            let arp = tokio::task::spawn_blocking(move || {
                arp::arp_scan_blocking(ifc, src_ip, mac, arp_targets, wait)
            })
            .await
            .map_err(|e| DiscoveryError::Io(io::Error::other(e.to_string())))??;
            all.extend(arp);
        }
        all.extend(icmp::sweep_v4(&v4, wait).await?);
    }

    if !v6.is_empty() {
        all.extend(icmp::sweep_v6(&v6, wait).await?);
    }

    Ok(merge_hosts(all))
}

/// Merge discovery results so each IP appears once, keeping the richest record —
/// a MAC-bearing hit (ARP) always wins over a MAC-less one (ICMP) for the same IP.
/// Order of first appearance is preserved.
pub fn merge_hosts(hosts: impl IntoIterator<Item = DiscoveredHost>) -> Vec<DiscoveredHost> {
    let mut out: Vec<DiscoveredHost> = Vec::new();
    for host in hosts {
        match out.iter_mut().find(|h| h.ip == host.ip) {
            Some(existing) => {
                // Keep the TTL whichever record carries it (ARP has none, ICMP does),
                // so a MAC-bearing ARP hit doesn't drop the ICMP OS signal (IMP-006).
                let ttl = existing.ttl.or(host.ttl);
                if existing.mac.is_none() && host.mac.is_some() {
                    *existing = host;
                }
                existing.ttl = ttl;
            }
            None => out.push(host),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(a: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, a))
    }

    #[test]
    fn merge_prefers_mac_bearing_record() {
        let mac = MacAddr::new(1, 2, 3, 4, 5, 6);
        let merged = merge_hosts([
            DiscoveredHost::new(ip(10), None, Method::IcmpEcho),
            DiscoveredHost::new(ip(10), Some(mac), Method::Arp),
            DiscoveredHost::new(ip(11), None, Method::IcmpEcho),
        ]);
        assert_eq!(merged.len(), 2);
        let ten = merged.iter().find(|h| h.ip == ip(10)).unwrap();
        assert_eq!(ten.mac, Some(mac), "ARP record should win for .10");
        assert_eq!(ten.method, Method::Arp);
    }

    #[test]
    fn merge_keeps_existing_mac_against_later_macless() {
        let mac = MacAddr::new(1, 2, 3, 4, 5, 6);
        let merged = merge_hosts([
            DiscoveredHost::new(ip(10), Some(mac), Method::Arp),
            DiscoveredHost::new(ip(10), None, Method::IcmpEcho),
        ]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].mac, Some(mac));
    }
}
