//! Stateless wide SYN sweep over raw sockets (IPv4 and IPv6, D-004).
//!
//! Fire a SYN at every (host, port) pair from one raw TCP socket and collect the
//! SYN-ACKs, with no per-connection state — the masscan-style fast/shallow pass
//! that feeds the stateful deep pass (C-005). Probes carry a recognisable source
//! port and sequence so replies can be matched without tracking connections.
//!
//! Needs `CAP_NET_RAW`; socket creation failure surfaces as
//! [`crate::discovery::DiscoveryError::Privilege`] so the caller can connect-scan
//! instead. The kernel, lacking a socket on our source port, will RST the targets'
//! SYN-ACKs — a harmless side effect of half-open scanning we accept for now.

use super::tcp::{self, PortReply};
use super::{HostPorts, OpenPort, ScanError};
use crate::discovery::DiscoveryError;
use crate::raw::{raw_socket, recv, recv_from, send_to};
use socket2::{Domain, Protocol};
use std::collections::{HashMap, HashSet};
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::time::Instant;

/// Recognisable source port ('PN') and sequence ('PNTS') stamped into our probes.
const SRC_PORT: u16 = 0x504e;
const SEQ: u32 = 0x504e_5453;

/// Sweep `ips` across `ports`, returning the open ports found per host (no banners;
/// that is the deep pass's job). Hosts with no open ports are simply absent.
pub async fn sweep(ips: &[IpAddr], ports: &[u16], wait: Duration) -> Result<Vec<HostPorts>, ScanError> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for ip in ips {
        match ip {
            IpAddr::V4(a) => v4.push(*a),
            IpAddr::V6(a) => v6.push(*a),
        }
    }

    let mut found: HashMap<IpAddr, Vec<OpenPort>> = HashMap::new();
    if !v4.is_empty() {
        for (ip, port) in sweep_v4(&v4, ports, wait).await? {
            found.entry(IpAddr::V4(ip)).or_default().push(OpenPort::tcp(port));
        }
    }
    if !v6.is_empty() {
        for (ip, port) in sweep_v6(&v6, ports, wait).await? {
            found.entry(IpAddr::V6(ip)).or_default().push(OpenPort::tcp(port));
        }
    }
    Ok(found
        .into_iter()
        .map(|(ip, mut open)| {
            open.sort_by_key(|p| p.port);
            HostPorts { ip, open }
        })
        .collect())
}

async fn sweep_v4(
    targets: &[Ipv4Addr],
    ports: &[u16],
    wait: Duration,
) -> Result<Vec<(Ipv4Addr, u16)>, ScanError> {
    let afd = AsyncFd::new(raw_socket(Domain::IPV4, Protocol::TCP)?)?;
    let want: HashSet<(Ipv4Addr, u16)> = product_v4(targets, ports);

    for &dst in targets {
        let src = egress_source_v4(dst).map_err(DiscoveryError::Io)?;
        for &port in ports {
            let pkt = tcp::build_syn_v4(src, dst, SRC_PORT, port, SEQ);
            send_to(&afd, &pkt, SocketAddr::new(IpAddr::V4(dst), 0)).await?;
        }
    }

    let mut open = Vec::new();
    let mut seen: HashSet<(Ipv4Addr, u16)> = HashSet::new();
    let deadline = Instant::now() + wait;
    let mut buf = [MaybeUninit::<u8>::uninit(); 1500];

    while Instant::now() < deadline && seen.len() < want.len() {
        let Some(data) = recv(&afd, &mut buf, deadline).await? else { break };
        if let Some((src_ip, reply)) = tcp::parse_tcp_reply_v4(data) {
            if reply.dst_port == SRC_PORT && reply.reply == PortReply::Open {
                let key = (src_ip, reply.src_port);
                if want.contains(&key) && seen.insert(key) {
                    open.push(key);
                }
            }
        }
    }
    Ok(open)
}

async fn sweep_v6(
    targets: &[Ipv6Addr],
    ports: &[u16],
    wait: Duration,
) -> Result<Vec<(Ipv6Addr, u16)>, ScanError> {
    let afd = AsyncFd::new(raw_socket(Domain::IPV6, Protocol::TCP)?)?;
    let want: HashSet<(Ipv6Addr, u16)> = product_v6(targets, ports);

    for &dst in targets {
        let src = egress_source_v6(dst).map_err(DiscoveryError::Io)?;
        for &port in ports {
            let pkt = tcp::build_syn_v6(src, dst, SRC_PORT, port, SEQ);
            send_to(&afd, &pkt, SocketAddr::new(IpAddr::V6(dst), 0)).await?;
        }
    }

    let mut open = Vec::new();
    let mut seen: HashSet<(Ipv6Addr, u16)> = HashSet::new();
    let deadline = Instant::now() + wait;
    let mut buf = [MaybeUninit::<u8>::uninit(); 1500];

    while Instant::now() < deadline && seen.len() < want.len() {
        // The kernel strips the IPv6 header; the responder address comes from recvfrom.
        let Some((data, from)) = recv_from(&afd, &mut buf, deadline).await? else { break };
        if let Some(reply) = tcp::parse_tcp_reply_v6(data) {
            if reply.dst_port == SRC_PORT && reply.reply == PortReply::Open {
                if let Some(sa) = from.as_socket_ipv6() {
                    let key = (*sa.ip(), reply.src_port);
                    if want.contains(&key) && seen.insert(key) {
                        open.push(key);
                    }
                }
            }
        }
    }
    Ok(open)
}

fn product_v4(targets: &[Ipv4Addr], ports: &[u16]) -> HashSet<(Ipv4Addr, u16)> {
    targets.iter().flat_map(|&ip| ports.iter().map(move |&p| (ip, p))).collect()
}

fn product_v6(targets: &[Ipv6Addr], ports: &[u16]) -> HashSet<(Ipv6Addr, u16)> {
    targets.iter().flat_map(|&ip| ports.iter().map(move |&p| (ip, p))).collect()
}

/// Discover the source address the kernel would use to reach `dst`, by connecting a
/// UDP socket (which sends nothing) and reading back its local address. We need it
/// to compute the TCP checksum's pseudo-header.
fn egress_source_v4(dst: Ipv4Addr) -> io::Result<Ipv4Addr> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    sock.connect((dst, 9))?;
    match sock.local_addr()?.ip() {
        IpAddr::V4(a) => Ok(a),
        IpAddr::V6(_) => Err(io::Error::other("expected IPv4 source address")),
    }
}

fn egress_source_v6(dst: Ipv6Addr) -> io::Result<Ipv6Addr> {
    let sock = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?;
    sock.connect((dst, 9))?;
    match sock.local_addr()?.ip() {
        IpAddr::V6(a) => Ok(a),
        IpAddr::V4(_) => Err(io::Error::other("expected IPv6 source address")),
    }
}
