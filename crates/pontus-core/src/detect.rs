//! Service/version detection (F-012).
//!
//! Detection sits behind the [`Detector`] trait (D-006): a modest native detector
//! ships by default and grows over time; an optional Nmap-backed detector that
//! shells out to the user's own `nmap` is a later addition.
//!
//! [`NativeDetector`] is **clean-room** — every rule here is written from public
//! protocol knowledge (banner grammars, well-known ports), never derived from
//! `nmap-service-probes` or any other licensed corpus (C-001).

/// An identified service on a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// Short service name, e.g. "ssh", "http".
    pub name: String,
    /// Software product, e.g. "OpenSSH", where the banner reveals it.
    pub product: Option<String>,
    /// Version string, e.g. "8.9p1", where the banner reveals it.
    pub version: Option<String>,
}

impl Service {
    fn named(name: &str) -> Self {
        Self { name: name.to_string(), product: None, version: None }
    }

    /// A compact "product version" string for display/storage, if any.
    pub fn version_string(&self) -> Option<String> {
        match (&self.product, &self.version) {
            (Some(p), Some(v)) => Some(format!("{p} {v}")),
            (Some(p), None) => Some(p.clone()),
            (None, Some(v)) => Some(v.clone()),
            (None, None) => None,
        }
    }
}

/// Identifies the service on a port from its protocol, number and (optional) banner.
pub trait Detector: Send + Sync {
    fn identify(&self, port: u16, proto: &str, banner: Option<&str>) -> Option<Service>;
}

/// The default clean-room detector: banner grammar first, then well-known ports.
pub struct NativeDetector;

impl Detector for NativeDetector {
    fn identify(&self, port: u16, proto: &str, banner: Option<&str>) -> Option<Service> {
        if let Some(text) = banner {
            if let Some(service) = from_banner(text) {
                return Some(service);
            }
        }
        default_for_port(proto, port)
    }
}

/// Recognise a service from the bytes it volunteered on connect.
fn from_banner(banner: &str) -> Option<Service> {
    let banner = banner.trim();
    if banner.is_empty() {
        return None;
    }
    let upper = banner.to_ascii_uppercase();

    // SSH: "SSH-<protoversion>-<softwareversion> [comments]" (RFC 4253 §4.2).
    if let Some(rest) = banner.strip_prefix("SSH-") {
        let software = rest.split_once('-').map_or("", |x| x.1);
        let token = software.split_whitespace().next().unwrap_or("");
        let (product, version) = split_product_version(token);
        return Some(Service { name: "ssh".to_string(), product, version });
    }

    // HTTP: a status line plus an optional Server header.
    if upper.contains("HTTP/1.") || upper.contains("HTTP/2") {
        return Some(Service { name: "http".to_string(), product: http_server(banner), version: None });
    }

    // Line-oriented greeters.
    if banner.starts_with("220") {
        if upper.contains("FTP") {
            return Some(Service::named("ftp"));
        }
        if upper.contains("SMTP") || upper.contains("ESMTP") {
            return Some(Service::named("smtp"));
        }
    }
    if banner.starts_with("+OK") {
        return Some(Service::named("pop3"));
    }
    if banner.starts_with("* OK") && upper.contains("IMAP") {
        return Some(Service::named("imap"));
    }

    None
}

/// Split a token like "OpenSSH_8.9p1" into ("OpenSSH", "8.9p1").
fn split_product_version(token: &str) -> (Option<String>, Option<String>) {
    if token.is_empty() {
        return (None, None);
    }
    match token.split_once('_') {
        Some((product, version)) => (Some(product.to_string()), Some(version.to_string())),
        None => (Some(token.to_string()), None),
    }
}

/// Pull the value of a `Server:` header out of an HTTP banner.
fn http_server(banner: &str) -> Option<String> {
    banner.lines().find_map(|line| {
        let lower = line.to_ascii_lowercase();
        lower.strip_prefix("server:").map(|_| line[line.find(':').unwrap() + 1..].trim().to_string())
    })
}

/// Fall back to the IANA-registered service for a well-known port.
fn default_for_port(proto: &str, port: u16) -> Option<Service> {
    let name = match (proto, port) {
        ("tcp", 21) => "ftp",
        ("tcp", 22) => "ssh",
        ("tcp", 23) => "telnet",
        ("tcp", 25) => "smtp",
        ("tcp", 110) => "pop3",
        ("tcp", 143) => "imap",
        ("tcp", 445) => "microsoft-ds",
        ("tcp", 3306) => "mysql",
        ("tcp", 3389) => "ms-wbt-server",
        ("tcp", 5432) => "postgresql",
        ("tcp", 6379) => "redis",
        ("tcp", 27017) => "mongodb",
        ("tcp", 80 | 8000 | 8080) => "http",
        ("tcp", 443 | 8443) => "https",
        ("udp", 53) => "dns",
        ("udp", 123) => "ntp",
        ("udp", 161) => "snmp",
        ("udp", 137) => "netbios-ns",
        ("udp", 500) => "isakmp",
        ("udp", 1900) => "upnp",
        ("udp", 5353) => "mdns",
        _ => return None,
    };
    Some(Service::named(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_banner_yields_product_and_version() {
        let d = NativeDetector;
        let s = d.identify(22, "tcp", Some("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3")).unwrap();
        assert_eq!(s.name, "ssh");
        assert_eq!(s.product.as_deref(), Some("OpenSSH"));
        assert_eq!(s.version.as_deref(), Some("8.9p1"));
        assert_eq!(s.version_string().as_deref(), Some("OpenSSH 8.9p1"));
    }

    #[test]
    fn http_banner_extracts_server_header() {
        let d = NativeDetector;
        let s = d.identify(80, "tcp", Some("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n")).unwrap();
        assert_eq!(s.name, "http");
        assert_eq!(s.product.as_deref(), Some("nginx/1.18.0"));
    }

    #[test]
    fn greeters_are_recognised() {
        let d = NativeDetector;
        assert_eq!(d.identify(21, "tcp", Some("220 ProFTPD Server ready")).unwrap().name, "ftp");
        assert_eq!(d.identify(25, "tcp", Some("220 mail ESMTP Postfix")).unwrap().name, "smtp");
        assert_eq!(d.identify(110, "tcp", Some("+OK POP3 ready")).unwrap().name, "pop3");
    }

    #[test]
    fn falls_back_to_well_known_port_without_a_banner() {
        let d = NativeDetector;
        assert_eq!(d.identify(443, "tcp", None).unwrap().name, "https");
        assert_eq!(d.identify(161, "udp", None).unwrap().name, "snmp");
        assert_eq!(d.identify(5353, "udp", None).unwrap().name, "mdns");
        assert!(d.identify(49152, "tcp", None).is_none());
    }

    #[test]
    fn banner_beats_port_default() {
        let d = NativeDetector;
        // An SSH server answering on a non-standard port is still ssh.
        let s = d.identify(2222, "tcp", Some("SSH-2.0-OpenSSH_9.6")).unwrap();
        assert_eq!(s.name, "ssh");
        assert_eq!(s.product.as_deref(), Some("OpenSSH"));
    }
}
