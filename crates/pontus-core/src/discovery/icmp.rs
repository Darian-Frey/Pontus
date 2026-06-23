//! Async ICMP echo sweeps over raw sockets (IPv4 and IPv6, D-004).
//!
//! One raw ICMP socket per family receives every reply; we send an echo request
//! to each target, then read replies until they stop arriving or the deadline
//! passes, matching them back to targets by source address and our identifier.
//!
//! Raw sockets need `CAP_NET_RAW`; creation failure maps to
//! [`DiscoveryError::Privilege`]. This module's socket I/O cannot run in an
//! unprivileged sandbox — its correctness rests on the unit-tested [`super::packet`]
//! layer plus an on-network run.

use super::packet;
use super::{DiscoveredHost, DiscoveryError, Method, priv_or_io};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::collections::HashSet;
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::time::Duration;
use tokio::io::unix::AsyncFd;
use tokio::time::{Instant, timeout};

/// Identifier stamped into our echo requests so we ignore unrelated ICMP traffic.
const ICMP_ID: u16 = 0x504e; // 'PN'
const PAYLOAD: &[u8] = b"pontus-discovery";

/// Ping every address in `targets` over IPv4; return those that answer.
pub async fn sweep_v4(targets: &[Ipv4Addr], wait: Duration) -> Result<Vec<DiscoveredHost>, DiscoveryError> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let socket = raw_socket(Domain::IPV4, Protocol::ICMPV4)?;
    let afd = AsyncFd::new(socket)?;

    for (seq, ip) in targets.iter().enumerate() {
        let pkt = packet::build_echo_request_v4(ICMP_ID, seq as u16, PAYLOAD);
        send_to(&afd, &pkt, SocketAddr::new(IpAddr::V4(*ip), 0)).await?;
    }

    let want: HashSet<Ipv4Addr> = targets.iter().copied().collect();
    let mut alive = Vec::new();
    let mut seen: HashSet<Ipv4Addr> = HashSet::new();
    let deadline = Instant::now() + wait;
    let mut buf = [MaybeUninit::<u8>::uninit(); 1500];

    while Instant::now() < deadline && seen.len() < want.len() {
        let Some(data) = recv(&afd, &mut buf, deadline).await? else { break };
        if let Some((src, reply)) = packet::parse_icmp_reply_v4(data) {
            if reply.identifier == ICMP_ID && want.contains(&src) && seen.insert(src) {
                alive.push(DiscoveredHost::new(IpAddr::V4(src), None, Method::IcmpEcho));
            }
        }
    }
    Ok(alive)
}

/// Ping every address in `targets` over IPv6; return those that answer.
pub async fn sweep_v6(targets: &[Ipv6Addr], wait: Duration) -> Result<Vec<DiscoveredHost>, DiscoveryError> {
    if targets.is_empty() {
        return Ok(Vec::new());
    }
    let socket = raw_socket(Domain::IPV6, Protocol::ICMPV6)?;
    // Have the kernel compute the ICMPv6 checksum (it covers the IPv6
    // pseudo-header, whose source address we do not pin here).
    set_icmpv6_checksum_offload(&socket)?;
    let afd = AsyncFd::new(socket)?;

    for (seq, ip) in targets.iter().enumerate() {
        let pkt = packet::build_echo_request_v6(ICMP_ID, seq as u16, PAYLOAD);
        send_to(&afd, &pkt, SocketAddr::new(IpAddr::V6(*ip), 0)).await?;
    }

    let want: HashSet<Ipv6Addr> = targets.iter().copied().collect();
    let mut alive = Vec::new();
    let mut seen: HashSet<Ipv6Addr> = HashSet::new();
    let deadline = Instant::now() + wait;
    let mut buf = [MaybeUninit::<u8>::uninit(); 1500];

    while Instant::now() < deadline && seen.len() < want.len() {
        // On IPv6 the kernel strips the IP header; the source comes from recvfrom.
        let Some((data, from)) = recv_from(&afd, &mut buf, deadline).await? else { break };
        if let Some(reply) = packet::parse_echo_reply_v6(data) {
            if reply.identifier == ICMP_ID {
                if let Some(sa) = from.as_socket_ipv6() {
                    let ip = *sa.ip();
                    if want.contains(&ip) && seen.insert(ip) {
                        alive.push(DiscoveredHost::new(IpAddr::V6(ip), None, Method::IcmpEcho));
                    }
                }
            }
        }
    }
    Ok(alive)
}

// ---- socket plumbing ------------------------------------------------------

fn raw_socket(domain: Domain, proto: Protocol) -> Result<Socket, DiscoveryError> {
    let socket = Socket::new(domain, Type::RAW, Some(proto)).map_err(priv_or_io)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Set `IPV6_CHECKSUM` so the kernel fills the ICMPv6 checksum at offset 2.
fn set_icmpv6_checksum_offload(socket: &Socket) -> io::Result<()> {
    let offset: libc::c_int = 2;
    // SAFETY: a valid socket fd, a correctly-sized c_int option value and matching
    // length; the call only reads `offset`.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IPV6,
            libc::IPV6_CHECKSUM,
            &offset as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

async fn send_to(afd: &AsyncFd<Socket>, buf: &[u8], dst: SocketAddr) -> Result<(), DiscoveryError> {
    let addr = SockAddr::from(dst);
    loop {
        let mut guard = afd.writable().await?;
        match guard.try_io(|inner| inner.get_ref().send_to(buf, &addr)) {
            Ok(res) => return res.map(|_| ()).map_err(DiscoveryError::Io),
            Err(_would_block) => continue,
        }
    }
}

/// Read one datagram (discarding the source) before `deadline`, or `None` on timeout.
async fn recv<'a>(
    afd: &AsyncFd<Socket>,
    buf: &'a mut [MaybeUninit<u8>],
    deadline: Instant,
) -> Result<Option<&'a [u8]>, DiscoveryError> {
    Ok(recv_from(afd, buf, deadline).await?.map(|(data, _)| data))
}

/// Read one datagram with its source address before `deadline`, or `None` on timeout.
async fn recv_from<'a>(
    afd: &AsyncFd<Socket>,
    buf: &'a mut [MaybeUninit<u8>],
    deadline: Instant,
) -> Result<Option<(&'a [u8], SockAddr)>, DiscoveryError> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        let mut guard = match timeout(remaining, afd.readable()).await {
            Ok(g) => g?,
            Err(_) => return Ok(None),
        };
        match guard.try_io(|inner| inner.get_ref().recv_from(buf)) {
            Ok(Ok((n, from))) => {
                // SAFETY: the kernel initialised the first `n` bytes of `buf`.
                let data = unsafe { &*(&buf[..n] as *const [MaybeUninit<u8>] as *const [u8]) };
                return Ok(Some((data, from)));
            }
            Ok(Err(e)) => return Err(DiscoveryError::Io(e)),
            Err(_would_block) => continue,
        }
    }
}
