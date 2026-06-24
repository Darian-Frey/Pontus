//! Traceroute — collect the router path to a host (F-009), the hop data the
//! topology graph is built from.
//!
//! Sends ICMP echo probes with an increasing IP TTL: each router that decrements
//! the TTL to zero replies with ICMP time-exceeded (revealing itself), and the
//! destination replies with an echo reply (ending the trace). The probe's
//! sequence number carries the TTL, so each reply is matched to the hop that
//! produced it (see [`crate::discovery::packet::parse_icmp_v4_message`]).
//!
//! IPv4 only for now; IPv6 traceroute (ICMPv6 hop-limit) is a follow-up. Needs
//! `CAP_NET_RAW`; socket creation failure surfaces as
//! [`DiscoveryError::Privilege`] so the caller can skip topology gracefully.

use crate::discovery::DiscoveryError;
use crate::discovery::packet::{self, IcmpV4Kind};
use crate::raw::{raw_socket, recv, send_to};
use socket2::{Domain, Protocol};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::time::Instant;

const TRACE_ID: u16 = 0x504e; // 'PN'
const PAYLOAD: &[u8] = b"pontus-trace";

/// One step on the path: the router/host that answered at this TTL, or `None` if
/// nothing replied within the timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hop {
    pub ttl: u8,
    pub ip: Option<IpAddr>,
}

/// Trace the path to `target`, up to `max_hops`, waiting `wait` for each hop's
/// reply. Stops early once the destination answers.
pub async fn trace(target: IpAddr, max_hops: u8, wait: Duration) -> Result<Vec<Hop>, DiscoveryError> {
    match target {
        IpAddr::V4(addr) => trace_v4(addr, max_hops, wait).await,
        // IPv6 traceroute (ICMPv6 hop-limit) not yet implemented; no hops rather
        // than an error, so a dual-stack scan still produces a v4 topology.
        IpAddr::V6(_) => Ok(Vec::new()),
    }
}

async fn trace_v4(target: Ipv4Addr, max_hops: u8, wait: Duration) -> Result<Vec<Hop>, DiscoveryError> {
    let socket = raw_socket(Domain::IPV4, Protocol::ICMPV4)?;
    let afd = AsyncFd::new(socket)?;
    let dst = SocketAddr::new(IpAddr::V4(target), 0);

    let mut hops = Vec::new();
    let mut buf = [MaybeUninit::<u8>::uninit(); 1500];

    for ttl in 1..=max_hops {
        afd.get_ref().set_ttl(ttl as u32).map_err(DiscoveryError::Io)?;
        let probe = packet::build_echo_request_v4(TRACE_ID, ttl as u16, PAYLOAD);
        send_to(&afd, &probe, dst).await?;

        let deadline = Instant::now() + wait;
        let mut hop_ip = None;
        let mut reached = false;

        // Read until a reply for *this* TTL arrives, or the per-hop timeout.
        while Instant::now() < deadline {
            let Some(data) = recv(&afd, &mut buf, deadline).await? else { break };
            let Some((source, kind)) = packet::parse_icmp_v4_message(data) else { continue };
            match kind {
                IcmpV4Kind::TimeExceeded { id, seq } if id == TRACE_ID && seq == ttl as u16 => {
                    hop_ip = Some(IpAddr::V4(source));
                    break;
                }
                IcmpV4Kind::EchoReply { id, seq } if id == TRACE_ID && seq == ttl as u16 => {
                    hop_ip = Some(IpAddr::V4(source));
                    reached = true;
                    break;
                }
                _ => continue,
            }
        }

        hops.push(Hop { ttl, ip: hop_ip });
        if reached {
            break;
        }
    }
    Ok(hops)
}

/// The local source address the kernel would use to reach `target` — the origin
/// node of the path (the scanner). Connects a UDP socket (sending nothing) and
/// reads back its local address.
pub fn egress_source(target: IpAddr) -> Option<IpAddr> {
    let bind: SocketAddr = match target {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = std::net::UdpSocket::bind(bind).ok()?;
    socket.connect(SocketAddr::new(target, 9)).ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}
