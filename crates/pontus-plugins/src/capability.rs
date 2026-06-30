//! Host-mediated plugin capabilities (F-021).
//!
//! Deeper plugins need to *actively probe* a service, but plugins must never get
//! ambient network authority — that would break the sandbox (D-003). Instead the
//! host hands a plugin a [`HostCapabilities`] object whose every operation is
//! mediated and **scope-enforced** (F-007): a plugin can only reach destinations
//! the host already authorised for the scan. [`NetCapabilities`] is the real
//! implementation (scope predicate + `ureq`); [`NoCapabilities`] grants nothing.

use std::collections::BTreeMap;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;

/// An HTTP response handed back to a plugin. Header names are lowercased so
/// plugins can look them up case-insensitively.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

/// What can go wrong when a plugin invokes a host capability.
#[derive(Debug, thiserror::Error)]
pub enum CapError {
    #[error("this plugin was not granted a network capability")]
    Unavailable,
    #[error("{0} is outside the authorised scope")]
    OutOfScope(String),
    #[error("invalid url: {0}")]
    BadUrl(String),
    #[error("http request failed: {0}")]
    Http(String),
}

/// Capabilities the host exposes to a plugin. Object-safe so a runner can hold a
/// `&dyn HostCapabilities` for the duration of a run.
pub trait HostCapabilities: Send + Sync {
    /// Fetch a URL over HTTP(S). The host resolves the destination and refuses
    /// anything outside the authorised scope before connecting.
    fn http_get(&self, url: &str) -> Result<HttpResponse, CapError>;
}

/// A capability set that grants nothing — the default for runs that don't pass
/// capabilities (passive plugins, unit tests).
pub struct NoCapabilities;

impl HostCapabilities for NoCapabilities {
    fn http_get(&self, _url: &str) -> Result<HttpResponse, CapError> {
        Err(CapError::Unavailable)
    }
}

/// Scope-enforced network capabilities backed by `ureq`. Every request is gated by
/// the `allow` predicate on the resolved destination IP, so a plugin can only
/// reach hosts already in the scan's scope.
pub struct NetCapabilities {
    allow: Box<dyn Fn(IpAddr) -> bool + Send + Sync>,
    timeout: Duration,
}

impl NetCapabilities {
    pub fn new(allow: impl Fn(IpAddr) -> bool + Send + Sync + 'static, timeout: Duration) -> Self {
        NetCapabilities { allow: Box::new(allow), timeout }
    }
}

impl HostCapabilities for NetCapabilities {
    fn http_get(&self, url: &str) -> Result<HttpResponse, CapError> {
        let (host, port) = parse_host_port(url)?;
        // Resolve and scope-check the destination before any connection (F-007).
        let addrs = (host.as_str(), port)
            .to_socket_addrs()
            .map_err(|e| CapError::BadUrl(format!("{host}: {e}")))?;
        if !addrs.into_iter().any(|a| (self.allow)(a.ip())) {
            return Err(CapError::OutOfScope(host));
        }

        let agent = ureq::AgentBuilder::new().timeout(self.timeout).build();
        let resp = agent.get(url).call().map_err(|e| CapError::Http(e.to_string()))?;
        let status = resp.status();
        let mut headers = BTreeMap::new();
        for name in resp.headers_names() {
            if let Some(v) = resp.header(&name) {
                headers.insert(name.to_ascii_lowercase(), v.to_string());
            }
        }
        let body = resp.into_string().unwrap_or_default();
        Ok(HttpResponse { status, headers, body })
    }
}

/// Extract `(host, port)` from a URL for the scope check. Handles `host`,
/// `host:port` and `[ipv6]:port`, defaulting the port from the scheme.
fn parse_host_port(url: &str) -> Result<(String, u16), CapError> {
    let (scheme, after) = url.split_once("://").ok_or_else(|| CapError::BadUrl(url.to_string()))?;
    let authority = after.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Err(CapError::BadUrl(url.to_string()));
    }
    let default_port = if scheme.eq_ignore_ascii_case("https") { 443 } else { 80 };

    if let Some(rest) = authority.strip_prefix('[') {
        // [ipv6] or [ipv6]:port
        let (h, tail) = rest.split_once(']').ok_or_else(|| CapError::BadUrl(url.to_string()))?;
        let port = tail.strip_prefix(':').and_then(|s| s.parse().ok()).unwrap_or(default_port);
        Ok((h.to_string(), port))
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        match p.parse::<u16>() {
            Ok(port) => Ok((h.to_string(), port)),
            Err(_) => Ok((authority.to_string(), default_port)), // colon but not a port
        }
    } else {
        Ok((authority.to_string(), default_port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_and_port_from_urls() {
        assert_eq!(parse_host_port("http://10.0.0.1/").unwrap(), ("10.0.0.1".into(), 80));
        assert_eq!(parse_host_port("https://example.com/x?y").unwrap(), ("example.com".into(), 443));
        assert_eq!(parse_host_port("http://host:8080/p").unwrap(), ("host".into(), 8080));
        assert_eq!(parse_host_port("http://[::1]:8000/").unwrap(), ("::1".into(), 8000));
        assert_eq!(parse_host_port("https://[2001:db8::1]/").unwrap(), ("2001:db8::1".into(), 443));
        assert!(parse_host_port("not-a-url").is_err());
    }

    #[test]
    fn no_capabilities_denies_http() {
        assert!(matches!(NoCapabilities.http_get("http://10.0.0.1/"), Err(CapError::Unavailable)));
    }

    #[test]
    fn out_of_scope_request_is_refused_before_fetch() {
        // allow nothing → the loopback request is refused on scope, never connecting.
        let caps = NetCapabilities::new(|_ip| false, Duration::from_millis(200));
        let err = caps.http_get("http://127.0.0.1:9/").unwrap_err();
        assert!(matches!(err, CapError::OutOfScope(_)), "got {err:?}");
    }
}
