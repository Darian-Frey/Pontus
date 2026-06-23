//! ARP sweep over the local segment (IPv4).
//!
//! ARP is the only discovery method that yields a MAC address — the strongest
//! identity signal (F-004) — so it is preferred for on-segment hosts. `pnet`'s
//! datalink channel is blocking, so the engine runs this under `spawn_blocking`.
//!
//! Opening a datalink channel needs `CAP_NET_RAW`; failure maps to
//! [`DiscoveryError::Privilege`].

use super::packet;
use super::{DiscoveredHost, DiscoveryError, Method, priv_or_io};
use pnet::datalink::{self, Channel, Config, NetworkInterface};
use pnet::util::MacAddr;
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

/// Blocking ARP sweep: broadcast a request for each target on `iface` and collect
/// the IP/MAC pairs that reply, up to `wait`. Intended to be wrapped in
/// `tokio::task::spawn_blocking`.
pub fn arp_scan_blocking(
    iface: NetworkInterface,
    src_ip: Ipv4Addr,
    src_mac: MacAddr,
    targets: Vec<Ipv4Addr>,
    wait: Duration,
) -> Result<Vec<DiscoveredHost>, DiscoveryError> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }

    let config = Config { read_timeout: Some(Duration::from_millis(100)), ..Default::default() };
    let (mut tx, mut rx) = match datalink::channel(&iface, config) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            return Err(DiscoveryError::Io(io::Error::other("unsupported datalink channel type")));
        }
        Err(e) => return Err(priv_or_io(e)),
    };

    for ip in &targets {
        let frame = packet::build_arp_request(src_mac, src_ip, *ip);
        if let Some(res) = tx.send_to(&frame, None) {
            res.map_err(DiscoveryError::Io)?;
        }
    }

    let want: HashSet<Ipv4Addr> = targets.iter().copied().collect();
    let mut found = Vec::new();
    let mut seen: HashSet<Ipv4Addr> = HashSet::new();
    let deadline = Instant::now() + wait;

    while Instant::now() < deadline && seen.len() < want.len() {
        match rx.next() {
            Ok(frame) => {
                if let Some((ip, mac)) = packet::parse_arp_reply(frame) {
                    if want.contains(&ip) && seen.insert(ip) {
                        found.push(DiscoveredHost::new(IpAddr::V4(ip), Some(mac), Method::Arp));
                    }
                }
            }
            // read_timeout fires as WouldBlock/TimedOut; keep polling until deadline.
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => return Err(DiscoveryError::Io(e)),
        }
    }
    Ok(found)
}
