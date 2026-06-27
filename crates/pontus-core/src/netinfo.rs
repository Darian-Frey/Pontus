//! The local machine's own network configuration (F-036): interfaces (IP, MAC,
//! netmask) and the ports it is listening on.
//!
//! This is "self" information — a live query of the host Pontus runs on, distinct
//! from the asset/observation model (which describes *other* hosts). Interfaces
//! come from `pnet`'s datalink layer; listening ports are read from `/proc/net`
//! (Linux). On a non-Linux host the interface list still works and the listening
//! list is simply empty.

use serde::Serialize;
use std::net::{Ipv4Addr, Ipv6Addr};

/// One address bound to an interface.
#[derive(Debug, Clone, Serialize)]
pub struct IfAddr {
    pub ip: String,
    pub prefix: u8,
    /// Dotted netmask for IPv4 (e.g. "255.255.255.0"); `None` for IPv6.
    pub netmask: Option<String>,
}

/// A local network interface.
#[derive(Debug, Clone, Serialize)]
pub struct Interface {
    pub name: String,
    pub mac: Option<String>,
    pub up: bool,
    pub loopback: bool,
    pub addrs: Vec<IfAddr>,
}

/// A socket the local machine is listening on.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ListenPort {
    pub proto: String, // "tcp", "tcp6", "udp", "udp6"
    pub address: String,
    pub port: u16,
}

/// The local machine's interfaces and listening sockets.
#[derive(Debug, Clone, Serialize, Default)]
pub struct LocalConfig {
    pub interfaces: Vec<Interface>,
    pub listening: Vec<ListenPort>,
}

/// Gather the local network configuration.
pub fn local_config() -> LocalConfig {
    LocalConfig { interfaces: interfaces(), listening: listening_ports() }
}

fn interfaces() -> Vec<Interface> {
    pnet::datalink::interfaces()
        .into_iter()
        .map(|i| {
            let addrs = i
                .ips
                .iter()
                .map(|net| {
                    let netmask = match net {
                        pnet::ipnetwork::IpNetwork::V4(n) => Some(n.mask().to_string()),
                        pnet::ipnetwork::IpNetwork::V6(_) => None,
                    };
                    IfAddr { ip: net.ip().to_string(), prefix: net.prefix(), netmask }
                })
                .collect();
            Interface {
                name: i.name.clone(),
                mac: i.mac.map(|m| m.to_string()),
                up: i.is_up(),
                loopback: i.is_loopback(),
                addrs,
            }
        })
        .collect()
}

/// Listening sockets from `/proc/net` (Linux). TCP in the LISTEN state and bound
/// UDP sockets; deduplicated and sorted by (port, proto).
fn listening_ports() -> Vec<ListenPort> {
    let mut out = Vec::new();
    // TCP LISTEN state is 0A; UDP "unconnected" (bound) is 07.
    parse_proc_net("/proc/net/tcp", "tcp", "0A", &mut out);
    parse_proc_net("/proc/net/tcp6", "tcp6", "0A", &mut out);
    parse_proc_net("/proc/net/udp", "udp", "07", &mut out);
    parse_proc_net("/proc/net/udp6", "udp6", "07", &mut out);
    out.sort_by(|a, b| a.port.cmp(&b.port).then(a.proto.cmp(&b.proto)));
    out.dedup();
    out
}

fn parse_proc_net(path: &str, proto: &str, want_state: &str, out: &mut Vec<ListenPort>) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return; // not Linux, or unreadable — leave the list as-is
    };
    let v6 = proto.ends_with('6');
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 || fields[3] != want_state {
            continue;
        }
        let Some((hex_ip, hex_port)) = fields[1].split_once(':') else { continue };
        let Ok(port) = u16::from_str_radix(hex_port, 16) else { continue };
        out.push(ListenPort { proto: proto.to_string(), address: parse_hex_addr(hex_ip, v6), port });
    }
}

/// Decode a `/proc/net` hex address (little-endian words) to a printable form.
fn parse_hex_addr(hex: &str, v6: bool) -> String {
    if !v6 && hex.len() == 8 {
        if let Ok(n) = u32::from_str_radix(hex, 16) {
            return Ipv4Addr::from(n.to_le_bytes()).to_string();
        }
    } else if v6 && hex.len() == 32 {
        let mut bytes = [0u8; 16];
        for i in 0..4 {
            if let Ok(word) = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16) {
                bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
        }
        return Ipv6Addr::from(bytes).to_string();
    }
    hex.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_proc_ipv4_addresses() {
        // /proc stores the address little-endian: 127.0.0.1 and 0.0.0.0.
        assert_eq!(parse_hex_addr("0100007F", false), "127.0.0.1");
        assert_eq!(parse_hex_addr("00000000", false), "0.0.0.0");
    }

    #[test]
    fn parses_a_listen_line() {
        // A synthetic /proc/net/tcp with one LISTEN (0A) on 0.0.0.0:80 and one
        // non-listening (01) row that must be ignored.
        let sample = "  sl  local_address rem_address   st\n   \
            0: 00000000:0050 00000000:0000 0A 00000000:00000000\n   \
            1: 0100007F:8A2F 0100007F:1F90 01 00000000:00000000\n";
        let path = std::env::temp_dir().join("pontus_proc_net_test_tcp");
        std::fs::write(&path, sample).unwrap();
        let mut out = Vec::new();
        parse_proc_net(path.to_str().unwrap(), "tcp", "0A", &mut out);
        let _ = std::fs::remove_file(&path);
        assert_eq!(out, vec![ListenPort { proto: "tcp".into(), address: "0.0.0.0".into(), port: 80 }]);
    }

    #[test]
    fn local_config_returns_interfaces() {
        // Every machine has at least a loopback interface.
        let cfg = local_config();
        assert!(cfg.interfaces.iter().any(|i| i.loopback), "loopback present: {:?}", cfg.interfaces);
    }
}
