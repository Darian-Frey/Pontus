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
use std::time::Duration;
use tokio::io::unix::{AsyncFd, AsyncFdReadyGuard};
use tokio::time::{Instant, sleep, timeout};

/// `ENOBUFS` (the kernel's transmit queue is momentarily full) is transient
/// backpressure on a wide sweep, not a real failure — pace and retry rather than
/// abort the scan. Unlike `WouldBlock` the socket still reports writable, so
/// awaiting readiness doesn't help; a short sleep lets the queue drain.
fn is_backpressure(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::ENOBUFS)
}

/// How many times to ride out sustained `ENOBUFS` for one probe before dropping it
/// (≈ a few ms); the sweep continues rather than failing.
const ENOBUFS_RETRIES: u32 = 64;

/// Create a non-blocking raw socket, mapping a permission error to
/// [`DiscoveryError::Privilege`].
pub(crate) fn raw_socket(domain: Domain, proto: Protocol) -> Result<Socket, DiscoveryError> {
    let socket = Socket::new(domain, Type::RAW, Some(proto)).map_err(priv_or_io)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// High-throughput batched sender for wide sweeps.
///
/// Holds a writability readiness guard across many sends and only re-awaits when
/// the kernel send buffer fills (`WouldBlock`), instead of awaiting once per
/// packet like [`send_to`]. This is the difference between a /16 sweep taking
/// minutes and taking seconds.
pub(crate) struct BatchSender<'a> {
    afd: &'a AsyncFd<Socket>,
    guard: Option<AsyncFdReadyGuard<'a, Socket>>,
}

impl<'a> BatchSender<'a> {
    pub(crate) fn new(afd: &'a AsyncFd<Socket>) -> Self {
        Self { afd, guard: None }
    }

    /// Send one datagram, reusing the held readiness when possible.
    pub(crate) async fn send(&mut self, buf: &[u8], addr: &SockAddr) -> Result<(), DiscoveryError> {
        let mut enobufs = 0u32;
        loop {
            if self.guard.is_none() {
                self.guard = Some(self.afd.writable().await?);
            }
            let guard = self.guard.as_mut().expect("guard set above");
            match guard.try_io(|inner| inner.get_ref().send_to(buf, addr)) {
                Ok(Ok(_)) => return Ok(()),
                Ok(Err(e)) if is_backpressure(&e) => {
                    enobufs += 1;
                    if enobufs > ENOBUFS_RETRIES {
                        return Ok(()); // drop this probe; the sweep keeps going
                    }
                    sleep(Duration::from_micros(200)).await; // let the tx queue drain
                }
                Ok(Err(e)) => return Err(DiscoveryError::Io(e)),
                // Send buffer full: drop readiness and re-await on the next iteration.
                Err(_would_block) => self.guard = None,
            }
        }
    }
}

/// Send one datagram, awaiting writability. The destination port is ignored for raw
/// sockets that carry their own transport header.
pub(crate) async fn send_to(
    afd: &AsyncFd<Socket>,
    buf: &[u8],
    dst: SocketAddr,
) -> Result<(), DiscoveryError> {
    let addr = SockAddr::from(dst);
    let mut enobufs = 0u32;
    loop {
        let mut guard = afd.writable().await?;
        match guard.try_io(|inner| inner.get_ref().send_to(buf, &addr)) {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) if is_backpressure(&e) => {
                enobufs += 1;
                if enobufs > ENOBUFS_RETRIES {
                    return Ok(()); // drop this probe; the sweep keeps going
                }
                sleep(Duration::from_micros(200)).await;
            }
            Ok(Err(e)) => return Err(DiscoveryError::Io(e)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn batch_sender_sustains_many_sends() {
        // A non-blocking UDP socket with a deliberately small send buffer, firing at
        // a loopback port nobody reads. Sending far more than the buffer holds forces
        // the WouldBlock -> re-await path, exercising BatchSender without a raw socket
        // or privilege. All sends must complete.
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        sock.set_nonblocking(true).unwrap();
        let _ = sock.set_send_buffer_size(8 << 10);
        let afd = AsyncFd::new(sock).unwrap();
        let addr = SockAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)));

        let mut sender = BatchSender::new(&afd);
        for _ in 0..20_000u32 {
            sender.send(b"pontus", &addr).await.unwrap();
        }
    }

    #[test]
    fn enobufs_is_classified_as_backpressure() {
        assert!(is_backpressure(&std::io::Error::from_raw_os_error(libc::ENOBUFS)));
        // A genuine error (e.g. permission denied) is not backpressure.
        assert!(!is_backpressure(&std::io::Error::from_raw_os_error(libc::EACCES)));
    }
}
