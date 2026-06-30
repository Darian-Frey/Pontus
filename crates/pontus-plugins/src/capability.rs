//! Host-mediated plugin capabilities (F-021).
//!
//! Deeper plugins need to *actively probe* a service, but plugins must never get
//! ambient network authority — that would break the sandbox (D-003). Instead the
//! host hands a plugin a [`HostCapabilities`] object whose every operation is
//! mediated and **scope-enforced** (F-007): a plugin can only reach destinations
//! the host already authorised for the scan. [`NetCapabilities`] is the real
//! implementation (scope predicate + `ureq`); [`NoCapabilities`] grants nothing.

use crate::snmp;
use std::collections::BTreeMap;
use std::io::Write;
use std::net::{IpAddr, ToSocketAddrs, UdpSocket};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Fixed SNMP request-id (the codec is single-shot; uniqueness across requests
/// isn't needed for a one-off GET).
const SNMP_REQUEST_ID: u32 = 0x70_6e_74_73; // "pnts"

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
    #[error("required tool not available: {0}")]
    Tool(String),
}

/// An SSH host key as reported by `ssh-keyscan` + `ssh-keygen -l`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshHostKey {
    pub algo: String,
    pub bits: u32,
    pub fingerprint: String,
}

/// An SMB share as reported by `smbclient -L -g` (Disk/IPC/Printer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbShare {
    pub kind: String,
    pub name: String,
    pub comment: String,
}

/// Capabilities the host exposes to a plugin. Object-safe so a runner can hold a
/// `&dyn HostCapabilities` for the duration of a run.
pub trait HostCapabilities: Send + Sync {
    /// Fetch a URL over HTTP(S). The host resolves the destination and refuses
    /// anything outside the authorised scope before connecting.
    fn http_get(&self, url: &str) -> Result<HttpResponse, CapError>;

    /// SNMP v2c GET of a single scalar OID from `host` (UDP 161) with `community`.
    /// `Ok(Some(value))` on a value, `Ok(None)` when there is no answer (timeout,
    /// closed, or an SNMP exception — i.e. "SNMP not readable here"), and `Err`
    /// only for misuse (bad OID, out of scope). Default: unavailable.
    fn snmp_get(&self, _host: &str, _community: &str, _oid: &str) -> Result<Option<String>, CapError> {
        Err(CapError::Unavailable)
    }

    /// Fetch a host's SSH host keys (algorithm, bit size, SHA-256 fingerprint) from
    /// `host:port`. Default: unavailable.
    fn ssh_hostkey(&self, _host: &str, _port: u16) -> Result<Vec<SshHostKey>, CapError> {
        Err(CapError::Unavailable)
    }

    /// List a host's SMB shares via an anonymous/null session. Default: unavailable.
    fn smb_shares(&self, _host: &str) -> Result<Vec<SmbShare>, CapError> {
        Err(CapError::Unavailable)
    }
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

    fn snmp_get(&self, host: &str, community: &str, oid: &str) -> Result<Option<String>, CapError> {
        let arcs = snmp::parse_oid(oid).ok_or_else(|| CapError::BadUrl(format!("oid {oid}")))?;
        // Resolve and scope-check the destination (UDP 161) before sending (F-007).
        let target = (host, 161u16)
            .to_socket_addrs()
            .map_err(|e| CapError::BadUrl(format!("{host}: {e}")))?
            .find(|a| (self.allow)(a.ip()))
            .ok_or_else(|| CapError::OutOfScope(host.to_string()))?;

        // Local/transient socket errors and timeouts mean "no SNMP answer" (Ok(None)),
        // not a hard error — a plugin probes many communities and most won't answer.
        let bind = if target.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let Ok(sock) = UdpSocket::bind(bind) else { return Ok(None) };
        let _ = sock.set_read_timeout(Some(self.timeout));
        let req = snmp::encode_get(community, SNMP_REQUEST_ID, &arcs);
        if sock.send_to(&req, target).is_err() {
            return Ok(None);
        }
        let mut buf = [0u8; 4096];
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => Ok(snmp::parse_get_response(&buf[..n])),
            Err(_) => Ok(None), // timeout → not SNMP-readable
        }
    }

    fn ssh_hostkey(&self, host: &str, port: u16) -> Result<Vec<SshHostKey>, CapError> {
        // Resolve and scope-check before connecting (F-007).
        (host, port)
            .to_socket_addrs()
            .map_err(|e| CapError::BadUrl(format!("{host}: {e}")))?
            .find(|a| (self.allow)(a.ip()))
            .ok_or_else(|| CapError::OutOfScope(host.to_string()))?;

        // Shell out to the user's own openssh tools (D-006): ssh-keyscan fetches the
        // keys, ssh-keygen -l fingerprints them. No SSH/crypto dependency in-tree.
        let secs = self.timeout.as_secs().max(1).to_string();
        let scan = Command::new("ssh-keyscan")
            .args(["-T", &secs, "-p", &port.to_string(), host])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| CapError::Tool("ssh-keyscan".into()))?;
        if scan.stdout.is_empty() {
            return Ok(Vec::new()); // no keys offered / host unreachable
        }

        let mut child = Command::new("ssh-keygen")
            .args(["-l", "-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| CapError::Tool("ssh-keygen".into()))?;
        // Drop stdin after writing so ssh-keygen sees EOF (output is small — no deadlock).
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(&scan.stdout);
        }
        let fp = child
            .wait_with_output()
            .map_err(|e| CapError::Tool(format!("ssh-keygen: {e}")))?;
        Ok(String::from_utf8_lossy(&fp.stdout).lines().filter_map(parse_keygen_line).collect())
    }

    fn smb_shares(&self, host: &str) -> Result<Vec<SmbShare>, CapError> {
        // Resolve and scope-check (SMB on 445) before connecting (F-007).
        (host, 445u16)
            .to_socket_addrs()
            .map_err(|e| CapError::BadUrl(format!("{host}: {e}")))?
            .find(|a| (self.allow)(a.ip()))
            .ok_or_else(|| CapError::OutOfScope(host.to_string()))?;

        // Shell out to the user's smbclient (D-006): null session, grepable list,
        // bounded by a per-operation timeout so an unresponsive host can't hang us.
        let secs = self.timeout.as_secs().max(1).to_string();
        let out = Command::new("smbclient")
            .args(["-N", "-g", "-t", &secs, "-L", &format!("//{host}")])
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| CapError::Tool("smbclient".into()))?;
        // Non-zero exit (access denied / not SMB) → no shares, not a hard error.
        Ok(String::from_utf8_lossy(&out.stdout).lines().filter_map(parse_smb_line).collect())
    }
}

/// Parse one `smbclient -L -g` line: `Type|Name|Comment`, keeping share types.
fn parse_smb_line(line: &str) -> Option<SmbShare> {
    let parts: Vec<&str> = line.splitn(3, '|').collect();
    if parts.len() != 3 {
        return None;
    }
    let kind = parts[0].trim();
    if !matches!(kind, "Disk" | "IPC" | "Printer") {
        return None; // skip Server/Workgroup info lines
    }
    Some(SmbShare {
        kind: kind.to_string(),
        name: parts[1].trim().to_string(),
        comment: parts[2].trim().to_string(),
    })
}

/// Parse one `ssh-keygen -l` line: `<bits> <SHA256:…> <comment…> (<TYPE>)`.
fn parse_keygen_line(line: &str) -> Option<SshHostKey> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    // The first token must be the bit count and the last `(TYPE)` — this rejects
    // ssh-keygen's `# host:port SSH-2.0-…` comment lines (no leading number).
    let bits: u32 = parts[0].parse().ok()?;
    let last = parts.last().unwrap();
    if !(last.starts_with('(') && last.ends_with(')')) {
        return None;
    }
    Some(SshHostKey {
        bits,
        algo: last.trim_matches(['(', ')']).to_string(),
        fingerprint: parts[1].to_string(),
    })
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

    #[test]
    fn parses_ssh_keygen_lines() {
        let ed = parse_keygen_line("256 SHA256:JNATBRyZ/E+abc host.example (ED25519)").unwrap();
        assert_eq!(ed, SshHostKey { algo: "ED25519".into(), bits: 256, fingerprint: "SHA256:JNATBRyZ/E+abc".into() });
        let rsa = parse_keygen_line("2048 SHA256:77ajKCbjbtq no comment (RSA)").unwrap();
        assert_eq!(rsa.algo, "RSA");
        assert_eq!(rsa.bits, 2048);
        // ssh-keygen error/comment lines (no fingerprint) are skipped.
        assert!(parse_keygen_line("# host.example:22 SSH-2.0-OpenSSH_9.6").is_none());
        assert!(parse_keygen_line("").is_none());
    }

    #[test]
    fn parses_smbclient_grepable_shares() {
        assert_eq!(
            parse_smb_line("Disk|backups|Nightly backups").unwrap(),
            SmbShare { kind: "Disk".into(), name: "backups".into(), comment: "Nightly backups".into() }
        );
        assert_eq!(parse_smb_line("IPC|IPC$|IPC Service").unwrap().name, "IPC$");
        // Server/Workgroup info lines and malformed lines are skipped.
        assert!(parse_smb_line("Server|FILESRV|comment").is_none());
        assert!(parse_smb_line("Workgroup|WORKGROUP|FILESRV").is_none());
        assert!(parse_smb_line("not piped").is_none());
    }

    #[test]
    fn out_of_scope_snmp_is_refused_and_bad_oid_errors() {
        let caps = NetCapabilities::new(|_ip| false, Duration::from_millis(200));
        assert!(matches!(
            caps.snmp_get("127.0.0.1", "public", "1.3.6.1.2.1.1.1.0"),
            Err(CapError::OutOfScope(_))
        ));
        // A malformed OID is misuse → BadUrl, regardless of scope.
        let any = NetCapabilities::new(|_ip| true, Duration::from_millis(200));
        assert!(matches!(any.snmp_get("127.0.0.1", "public", "not-an-oid"), Err(CapError::BadUrl(_))));
    }
}
