//! Scope enforcement (F-007).
//!
//! Scope is a safety feature, not a setting. There is deliberately **no**
//! constructor that yields an allow-everything scope and **no** flag to disable
//! the check: a [`Scope`] must name at least one network range, and every target
//! is checked against it before a packet is sent. The enforcement lives in the
//! headless core so both the CLI and the GUI inherit it unconditionally.

use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScopeError {
    #[error("scope must declare at least one network range")]
    Empty,
    #[error("invalid scope specification '{0}'")]
    Invalid(String),
    #[error("target {0} is outside the declared scope")]
    OutOfScope(IpAddr),
}

/// A non-empty set of authorised network ranges (IPv4 and/or IPv6, D-004).
#[derive(Debug, Clone)]
pub struct Scope {
    nets: Vec<IpNet>,
}

impl Scope {
    /// Build a scope from explicit ranges. Rejects an empty set — a scope that
    /// authorises nothing is a programming error, not a way to scan everything.
    pub fn new(nets: Vec<IpNet>) -> Result<Self, ScopeError> {
        if nets.is_empty() {
            return Err(ScopeError::Empty);
        }
        Ok(Self { nets })
    }

    /// Parse scope specifications. Each entry may be a CIDR (`192.168.1.0/24`,
    /// `2001:db8::/32`) or a bare address (treated as a single-host range).
    pub fn parse<I, S>(specs: I) -> Result<Self, ScopeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut nets = Vec::new();
        for spec in specs {
            let spec = spec.as_ref().trim();
            if spec.is_empty() {
                continue;
            }
            nets.push(parse_cidr_or_host(spec)?);
        }
        Self::new(nets)
    }

    /// True if `ip` falls within any authorised range.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(&ip))
    }

    /// Gatekeeper called on the scan path before any packet leaves: returns
    /// [`ScopeError::OutOfScope`] for a target outside the declared ranges.
    pub fn ensure(&self, ip: IpAddr) -> Result<(), ScopeError> {
        if self.contains(ip) {
            Ok(())
        } else {
            Err(ScopeError::OutOfScope(ip))
        }
    }

    /// The authorised ranges, for display and the audit record.
    pub fn nets(&self) -> &[IpNet] {
        &self.nets
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rendered: Vec<String> = self.nets.iter().map(|n| n.to_string()).collect();
        f.write_str(&rendered.join(","))
    }
}

/// Parse one entry as a CIDR (`192.168.1.0/24`), falling back to a bare host
/// address (`192.168.1.5` → a single-host range). Shared by scope parsing and the
/// CLI's target parsing so both accept the same notation.
pub fn parse_cidr_or_host(spec: &str) -> Result<IpNet, ScopeError> {
    if let Ok(net) = IpNet::from_str(spec) {
        return Ok(net);
    }
    match IpAddr::from_str(spec) {
        Ok(IpAddr::V4(a)) => Ok(IpNet::from(ipnet::Ipv4Net::new(a, 32).unwrap())),
        Ok(IpAddr::V6(a)) => Ok(IpNet::from(ipnet::Ipv6Net::new(a, 128).unwrap())),
        Err(_) => Err(ScopeError::Invalid(spec.to_string())),
    }
}
