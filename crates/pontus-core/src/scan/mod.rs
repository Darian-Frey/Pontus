//! Hybrid port scanning (F-002).
//!
//! The pipeline is a stateless wide sweep feeding a stateful deep pass (C-005):
//!
//! 1. **Stateless SYN sweep** ([`stateless`]) — fire raw SYN probes across the
//!    port space and collect SYN-ACKs with no per-connection state. Fast and
//!    shallow; needs `CAP_NET_RAW`.
//! 2. **Stateful deep pass** ([`stateful`]) — for each candidate-open port, a real
//!    TCP connect confirms it and grabs a banner. Unprivileged.
//!
//! Without raw-socket privilege the sweep is skipped and the deep pass connect-scans
//! the requested ports directly — slower, but the same results.

pub mod stateful;
pub mod stateless;
pub mod tcp;
pub mod udp;
pub mod udp_probes;

/// Render service-banner / probe-response bytes as a single safe ASCII line: drop
/// leading/trailing whitespace and control bytes (e.g. a trailing CRLF), then map
/// any interior non-graphic byte to '.'. Shared by the TCP banner grab and UDP
/// response capture.
pub(crate) fn sanitise_banner(bytes: &[u8]) -> String {
    let start = bytes.iter().position(u8::is_ascii_graphic).unwrap_or(0);
    let end = bytes.iter().rposition(u8::is_ascii_graphic).map_or(start, |i| i + 1);
    bytes[start..end]
        .iter()
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
        .collect()
}

use crate::discovery::DiscoveryError;
use std::net::IpAddr;

/// An open port found on a host, optionally with a service banner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPort {
    pub port: u16,
    /// "tcp" today; UDP scanning is a later addition.
    pub proto: &'static str,
    /// First bytes the service volunteered on connect, if any.
    pub banner: Option<String>,
}

impl OpenPort {
    pub fn tcp(port: u16) -> Self {
        Self { port, proto: "tcp", banner: None }
    }
}

/// Passive TCP/IP-stack fingerprint signals read from a host's SYN-ACK (F-013).
///
/// The p0f-style discriminators: the initial TTL, the advertised window, the
/// don't-fragment bit, and — most telling — the *order* of TCP options the stack
/// emits (encoded one letter each: `M`SS, `S`ACK-permitted, `T`imestamp, `N`OP,
/// `W`indow-scale, `E`OL). Different stacks order and include these differently,
/// so the layout discriminates families that share a TTL (e.g. Linux vs macOS).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StackSignature {
    /// IPv4 TTL; `None` over IPv6 (the kernel strips the header) or the connect path.
    pub ttl: Option<u8>,
    /// Advertised TCP window.
    pub window: Option<u16>,
    /// IPv4 don't-fragment bit; `None` over IPv6 or the connect path.
    pub df: Option<bool>,
    /// TCP-option layout string, e.g. "MSTNW" (Linux) or "MNWNNS" (Windows).
    pub opts_layout: Option<String>,
}

/// The open ports found on one host, plus the passive OS fingerprint signals
/// captured from its SYN-ACK during the stateless sweep (F-013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPorts {
    pub ip: IpAddr,
    pub open: Vec<OpenPort>,
    /// SYN-ACK stack signature, when the raw sweep ran (default on the connect path).
    pub stack: StackSignature,
}

/// Knobs for the hybrid scan.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub ports: Vec<u16>,
    /// How long the stateless sweep listens for SYN-ACKs.
    pub sweep_wait: std::time::Duration,
    /// Per-port connect timeout in the deep pass.
    pub connect_timeout: std::time::Duration,
    /// How long to wait for a banner after connecting.
    pub banner_wait: std::time::Duration,
}

/// Reuse the discovery error taxonomy (privilege vs. I/O) for scanning too.
pub type ScanError = DiscoveryError;

/// Hybrid scan of `ips` (F-002): a stateless SYN sweep finds candidate-open ports,
/// then the stateful deep pass confirms each and grabs a banner. Without
/// `CAP_NET_RAW` the sweep is unavailable, so we connect-scan the full port list
/// directly — slower, same results.
///
/// Returns one [`HostPorts`] per host that has at least one open port.
pub async fn scan_hosts(ips: &[IpAddr], cfg: &ScanConfig) -> Result<Vec<HostPorts>, ScanError> {
    match stateless::sweep(ips, &cfg.ports, cfg.sweep_wait).await {
        Ok(candidates) => {
            // Deep pass: confirm each candidate-open port and grab its banner.
            let mut out = Vec::with_capacity(candidates.len());
            for hp in candidates {
                let ports: Vec<u16> = hp.open.iter().map(|p| p.port).collect();
                let mut confirmed = stateful::connect_scan(hp.ip, &ports, cfg).await;
                // Carry the sweep's stack signature onto the confirmed result — the
                // connect pass has no raw access to it (F-013).
                confirmed.stack = hp.stack.clone();
                if !confirmed.open.is_empty() {
                    out.push(confirmed);
                }
            }
            Ok(out)
        }
        Err(e) if e.is_privilege() => {
            // Unprivileged fallback: connect-scan the full port list per host.
            let mut out = Vec::new();
            for &ip in ips {
                let hp = stateful::connect_scan(ip, &cfg.ports, cfg).await;
                if !hp.open.is_empty() {
                    out.push(hp);
                }
            }
            Ok(out)
        }
        Err(e) => Err(e),
    }
}
