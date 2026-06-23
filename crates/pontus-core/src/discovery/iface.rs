//! Local interface selection for link-layer discovery (ARP).
//!
//! ARP only works on the segment the host shares with us, so we need the local
//! interface whose subnet contains the target, plus its source IP and MAC to put
//! in the request.

use pnet::datalink::{self, NetworkInterface};
use pnet::ipnetwork::{IpNetwork, Ipv4Network};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

/// A usable local interface for ARP, resolved for a particular target.
#[derive(Debug, Clone)]
pub struct LocalIface {
    pub iface: NetworkInterface,
    pub network: Ipv4Network,
    pub src_ip: Ipv4Addr,
    pub mac: MacAddr,
}

/// Find an up, non-loopback interface with a real MAC whose IPv4 subnet contains
/// `target`. Returns `None` when the target is not on any local segment (i.e. it is
/// routed, and must be reached by ICMP instead of ARP).
pub fn local_v4_iface_for(target: Ipv4Addr) -> Option<LocalIface> {
    for iface in datalink::interfaces() {
        if iface.is_loopback() || !iface.is_up() {
            continue;
        }
        let mac = match iface.mac {
            Some(m) if m != MacAddr::zero() => m,
            _ => continue,
        };
        for ipn in &iface.ips {
            if let IpNetwork::V4(net) = ipn {
                if net.contains(target) {
                    return Some(LocalIface {
                        iface: iface.clone(),
                        network: *net,
                        src_ip: net.ip(),
                        mac,
                    });
                }
            }
        }
    }
    None
}
