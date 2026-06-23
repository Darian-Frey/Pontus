//! Shared async raw-socket plumbing for the ICMP discovery sweep and the TCP SYN
//! scan sweep. Both send a batch of crafted packets on one non-blocking raw socket
//! and read replies until a deadline; this module is that common machinery.
//!
//! Raw sockets need `CAP_NET_RAW`; creation maps `EPERM`/`EACCES` to
//! [`DiscoveryError::Privilege`] so callers can fall back to an unprivileged path.

use crate::discovery::{DiscoveryError, priv_or_io};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::mem::MaybeUninit;
use std::net::SocketAddr;
use tokio::io::unix::AsyncFd;
use tokio::time::{Instant, timeout};

/// Create a non-blocking raw socket, mapping a permission error to
/// [`DiscoveryError::Privilege`].
pub(crate) fn raw_socket(domain: Domain, proto: Protocol) -> Result<Socket, DiscoveryError> {
    let socket = Socket::new(domain, Type::RAW, Some(proto)).map_err(priv_or_io)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Send one datagram, awaiting writability. The destination port is ignored for raw
/// sockets that carry their own transport header.
pub(crate) async fn send_to(
    afd: &AsyncFd<Socket>,
    buf: &[u8],
    dst: SocketAddr,
) -> Result<(), DiscoveryError> {
    let addr = SockAddr::from(dst);
    loop {
        let mut guard = afd.writable().await?;
        match guard.try_io(|inner| inner.get_ref().send_to(buf, &addr)) {
            Ok(res) => return res.map(|_| ()).map_err(DiscoveryError::Io),
            Err(_would_block) => continue,
        }
    }
}

/// Read one datagram with its source address before `deadline`, or `None` on timeout.
pub(crate) async fn recv_from<'a>(
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

/// Read one datagram before `deadline`, discarding the source, or `None` on timeout.
pub(crate) async fn recv<'a>(
    afd: &AsyncFd<Socket>,
    buf: &'a mut [MaybeUninit<u8>],
    deadline: Instant,
) -> Result<Option<&'a [u8]>, DiscoveryError> {
    Ok(recv_from(afd, buf, deadline).await?.map(|(data, _)| data))
}
