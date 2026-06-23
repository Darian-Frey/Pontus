//! Pure TCP packet construction and parsing for the stateless SYN sweep.
//!
//! I/O-free and unit-tested (checksums over the IP pseudo-header, flag
//! classification, IP-header unwrapping). The raw-socket sweep in [`super::stateless`]
//! builds on these; isolating the byte work is what lets it be trusted without a
//! privileged socket in the test loop.

use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket, ipv4_checksum, ipv6_checksum};
use std::net::{Ipv4Addr, Ipv6Addr};

/// A bare SYN segment is 20 bytes (no options).
pub const TCP_HEADER_LEN: usize = 20;
const DEFAULT_WINDOW: u16 = 64240;

/// What a probed port's response tells us.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortReply {
    /// SYN+ACK — the port is open.
    Open,
    /// RST — the port is closed (host reachable, nothing listening).
    Closed,
    /// Anything else we don't act on.
    Other,
}

/// A parsed TCP response, reduced to what the sweep matches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpReply {
    /// The responder's port (the port we probed).
    pub src_port: u16,
    /// Our source port (lets us confirm the reply is to our probe).
    pub dst_port: u16,
    pub reply: PortReply,
}

/// Classify TCP control flags into a port verdict.
pub fn classify(flags: u8) -> PortReply {
    let syn = flags & TcpFlags::SYN != 0;
    let ack = flags & TcpFlags::ACK != 0;
    let rst = flags & TcpFlags::RST != 0;
    if syn && ack {
        PortReply::Open
    } else if rst {
        PortReply::Closed
    } else {
        PortReply::Other
    }
}

// ---- IPv4 -----------------------------------------------------------------

/// Build a TCP SYN segment (no IP header — the kernel prepends it on a raw TCP
/// socket) with its checksum computed over the IPv4 pseudo-header.
pub fn build_syn_v4(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16, seq: u32) -> Vec<u8> {
    let mut buf = vec![0u8; TCP_HEADER_LEN];
    let mut tcp = MutableTcpPacket::new(&mut buf).expect("20 bytes");
    tcp.set_source(src_port);
    tcp.set_destination(dst_port);
    tcp.set_sequence(seq);
    tcp.set_data_offset(5); // 20 bytes / 4
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_window(DEFAULT_WINDOW);
    let cs = ipv4_checksum(&tcp.to_immutable(), &src, &dst);
    tcp.set_checksum(cs);
    buf
}

/// Parse a datagram received on a raw IPv4 TCP socket (IP header included) into the
/// responder address and TCP verdict, if it is TCP.
pub fn parse_tcp_reply_v4(buf: &[u8]) -> Option<(Ipv4Addr, TcpReply)> {
    let ip = Ipv4Packet::new(buf)?;
    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
        return None;
    }
    let tcp = TcpPacket::new(ip.payload())?;
    Some((
        ip.get_source(),
        TcpReply {
            src_port: tcp.get_source(),
            dst_port: tcp.get_destination(),
            reply: classify(tcp.get_flags()),
        },
    ))
}

// ---- IPv6 -----------------------------------------------------------------

/// Build a TCP SYN segment with its checksum over the IPv6 pseudo-header.
pub fn build_syn_v6(src: Ipv6Addr, dst: Ipv6Addr, src_port: u16, dst_port: u16, seq: u32) -> Vec<u8> {
    let mut buf = vec![0u8; TCP_HEADER_LEN];
    let mut tcp = MutableTcpPacket::new(&mut buf).expect("20 bytes");
    tcp.set_source(src_port);
    tcp.set_destination(dst_port);
    tcp.set_sequence(seq);
    tcp.set_data_offset(5);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_window(DEFAULT_WINDOW);
    let cs = ipv6_checksum(&tcp.to_immutable(), &src, &dst);
    tcp.set_checksum(cs);
    buf
}

/// Parse a raw IPv6 TCP segment (no IP header — the kernel strips it on receive).
/// The responder address comes from the socket, not the packet.
pub fn parse_tcp_reply_v6(tcp_bytes: &[u8]) -> Option<TcpReply> {
    let tcp = TcpPacket::new(tcp_bytes)?;
    Some(TcpReply {
        src_port: tcp.get_source(),
        dst_port: tcp.get_destination(),
        reply: classify(tcp.get_flags()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ipv4::MutableIpv4Packet;

    #[test]
    fn syn_v4_has_valid_checksum_and_flags() {
        let src = Ipv4Addr::new(192, 168, 1, 50);
        let dst = Ipv4Addr::new(192, 168, 1, 1);
        let buf = build_syn_v4(src, dst, 40000, 443, 0xDEAD_BEEF);
        let tcp = TcpPacket::new(&buf).unwrap();
        assert_eq!(tcp.get_flags(), TcpFlags::SYN);
        assert_eq!(tcp.get_destination(), 443);
        assert_eq!(tcp.get_sequence(), 0xDEAD_BEEF);
        // A correct checksum recomputes to the stored value.
        assert_eq!(ipv4_checksum(&tcp, &src, &dst), tcp.get_checksum());
    }

    #[test]
    fn syn_v6_has_valid_checksum() {
        let src: Ipv6Addr = "2001:db8::50".parse().unwrap();
        let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let buf = build_syn_v6(src, dst, 40000, 80, 1);
        let tcp = TcpPacket::new(&buf).unwrap();
        assert_eq!(ipv6_checksum(&tcp, &src, &dst), tcp.get_checksum());
        let parsed = parse_tcp_reply_v6(&buf).unwrap();
        assert_eq!(parsed.src_port, 40000);
        assert_eq!(parsed.dst_port, 80);
    }

    #[test]
    fn classify_covers_open_closed_other() {
        assert_eq!(classify(TcpFlags::SYN | TcpFlags::ACK), PortReply::Open);
        assert_eq!(classify(TcpFlags::RST), PortReply::Closed);
        assert_eq!(classify(TcpFlags::RST | TcpFlags::ACK), PortReply::Closed);
        assert_eq!(classify(TcpFlags::SYN), PortReply::Other);
    }

    #[test]
    fn tcp_reply_v4_unwraps_ip_header() {
        // A SYN+ACK from 192.168.1.1:443 to our port 40000.
        let synack = {
            let src = Ipv4Addr::new(192, 168, 1, 1);
            let dst = Ipv4Addr::new(192, 168, 1, 50);
            let mut b = vec![0u8; TCP_HEADER_LEN];
            let mut tcp = MutableTcpPacket::new(&mut b).unwrap();
            tcp.set_source(443);
            tcp.set_destination(40000);
            tcp.set_data_offset(5);
            tcp.set_flags(TcpFlags::SYN | TcpFlags::ACK);
            let cs = ipv4_checksum(&tcp.to_immutable(), &src, &dst);
            tcp.set_checksum(cs);
            b
        };
        let mut ipbuf = vec![0u8; 20 + synack.len()];
        let mut ip = MutableIpv4Packet::new(&mut ipbuf).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((20 + synack.len()) as u16);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(Ipv4Addr::new(192, 168, 1, 1));
        ip.set_payload(&synack);

        let (src, reply) = parse_tcp_reply_v4(&ipbuf).unwrap();
        assert_eq!(src, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(reply.src_port, 443);
        assert_eq!(reply.dst_port, 40000);
        assert_eq!(reply.reply, PortReply::Open);
    }
}
