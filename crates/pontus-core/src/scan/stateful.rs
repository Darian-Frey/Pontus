//! Stateful deep pass: a real TCP connect that confirms an open port and grabs a
//! short service banner. Unprivileged, so it doubles as the fallback scan when raw
//! sockets are unavailable.

use super::{HostPorts, OpenPort, ScanConfig};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// Connect-scan one host across `ports`, returning the confirmed-open ports with
/// banners where a service volunteered one. Ports are probed concurrently.
pub async fn connect_scan(ip: IpAddr, ports: &[u16], cfg: &ScanConfig) -> HostPorts {
    let connect_timeout = cfg.connect_timeout;
    let banner_wait = cfg.banner_wait;

    let mut set: JoinSet<Option<OpenPort>> = JoinSet::new();
    for &port in ports {
        set.spawn(async move { probe_port(ip, port, connect_timeout, banner_wait).await });
    }

    let mut open = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok(Some(p)) = res {
            open.push(p);
        }
    }
    open.sort_by_key(|p| p.port);
    HostPorts { ip, open }
}

async fn probe_port(ip: IpAddr, port: u16, connect_timeout: Duration, banner_wait: Duration) -> Option<OpenPort> {
    let addr = SocketAddr::new(ip, port);
    let stream = match timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        // timeout, refused or unreachable: not open.
        _ => return None,
    };
    let banner = grab_banner(stream, banner_wait).await;
    Some(OpenPort { port, proto: "tcp", banner })
}

/// Read whatever the service sends first (many announce themselves: SSH, SMTP,
/// FTP). Silence within `wait` is normal (e.g. HTTP awaits a request) and yields
/// no banner.
async fn grab_banner(mut stream: TcpStream, wait: Duration) -> Option<String> {
    let mut buf = [0u8; 256];
    match timeout(wait, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => Some(sanitise(&buf[..n])),
        _ => None,
    }
}

/// Render banner bytes as a single safe ASCII line: drop leading/trailing
/// whitespace and control bytes (e.g. the CRLF many banners end with), then map
/// any interior non-graphic byte to '.'.
fn sanitise(bytes: &[u8]) -> String {
    let start = bytes.iter().position(u8::is_ascii_graphic).unwrap_or(0);
    let end = bytes.iter().rposition(u8::is_ascii_graphic).map_or(start, |i| i + 1);
    bytes[start..end]
        .iter()
        .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
        .collect()
}
