//! Reverse-DNS resolution to populate the hostname identity tier (F-004).
//!
//! Uses the system resolver via `getnameinfo`, so it honours `/etc/hosts`, mDNS
//! and the local DNS server (which is where names like `Pixel-7.powerhub` come
//! from), not just public DNS. The lookup queries the resolver, never the scanned
//! host, so it sits outside scope enforcement — it sends no packets to the target.
//!
//! `getnameinfo` is blocking; callers on an async runtime should run it via
//! `spawn_blocking`.

use socket2::SockAddr;
use std::ffi::CStr;
use std::net::{IpAddr, SocketAddr};

/// Resolve `ip` to a hostname via the system resolver, or `None` if it has no PTR
/// record / cannot be resolved.
pub fn reverse_lookup(ip: IpAddr) -> Option<String> {
    let sa = SockAddr::from(SocketAddr::new(ip, 0));
    // NI_MAXHOST is 1025; size the buffer to match.
    let mut host = [0 as libc::c_char; 1025];

    // SAFETY: `sa` owns a valid sockaddr of length `sa.len()`; `host` is a writable
    // buffer of `host.len()` bytes; the service buffer is null with length 0, which
    // getnameinfo accepts. NI_NAMEREQD makes the call fail rather than return a
    // numeric string when there is no name.
    let rc = unsafe {
        libc::getnameinfo(
            sa.as_ptr(),
            sa.len(),
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if rc != 0 {
        return None;
    }

    // SAFETY: on success getnameinfo writes a NUL-terminated C string into `host`.
    let name = unsafe { CStr::from_ptr(host.as_ptr()) }.to_str().ok()?.to_string();
    if name.is_empty() { None } else { Some(name) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn loopback_lookup_is_safe_and_well_formed() {
        // The result is environment-dependent (usually "localhost" via /etc/hosts),
        // so we don't assert a specific name — only that the FFI path is sound and
        // any returned name is a sane single token. This guards the unsafe block
        // against buffer/termination regressions.
        if let Some(name) = reverse_lookup(IpAddr::V4(Ipv4Addr::LOCALHOST)) {
            assert!(!name.is_empty());
            assert!(!name.contains(char::is_whitespace), "hostname is a single token");
        }
    }
}
