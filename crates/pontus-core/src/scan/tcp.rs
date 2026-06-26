//! Pure TCP packet construction and parsing for the stateless SYN sweep.
//!
//! I/O-free and unit-tested (checksums over the IP pseudo-header, flag
//! classification, IP-header unwrapping). The raw-socket sweep in [`super::stateless`]
//! builds on these; isolating the byte work is what lets it be trusted without a
//! privileged socket in the test loop.

use super::StackSignature;
use pnet::packet::Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Flags, Ipv4Packet};
use pnet::packet::tcp::{
    MutableTcpPacket, TcpFlags, TcpOption, TcpOptionNumbers, TcpPacket, ipv4_checksum,
    ipv6_checksum,
};
use std::net::{Ipv4Addr, Ipv6Addr};

/// A bare TCP header is 20 bytes (before options).
pub const TCP_HEADER_LEN: usize = 20;
const DEFAULT_WINDOW: u16 = 64240;

/// The TCP options our SYN probes carry: MSS, SACK-permitted, Timestamp, NOP,
/// Window-scale — 20 bytes, a multiple of 4 so the header needs no padding.
///
/// Offering these is what makes a responder echo its *own* option ordering in the
/// SYN-ACK, the OS-discriminating signal for fingerprinting (F-013). A bare SYN
/// (no options) elicits only an MSS in reply regardless of OS, which tells us
/// nothing — every stack looks identical. The values are unremarkable client
/// defaults; only the responder's reply ordering is read back.
const SYN_OPTS_LEN: usize = 20;
const SYN_LEN: usize = TCP_HEADER_LEN + SYN_OPTS_LEN;

fn syn_options() -> [TcpOption; 5] {
    [
        TcpOption::mss(1460),
        TcpOption::sack_perm(),
        TcpOption::timestamp(0x506f_6e74, 0), // "Pont"
        TcpOption::nop(),
        TcpOption::wscale(7),
    ]
}

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

/// A parsed TCP response, reduced to what the sweep matches on plus the passive
/// OS fingerprint signature carried by the reply (F-013).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpReply {
    /// The responder's port (the port we probed).
    pub src_port: u16,
    /// Our source port (lets us confirm the reply is to our probe).
    pub dst_port: u16,
    pub reply: PortReply,
    /// Passive TCP/IP-stack signature (TTL, window, DF, option layout).
    pub sig: StackSignature,
}

/// Read the TCP-option layout from a segment: one letter per option in the order
/// they appear (`M`SS, `S`ACK-permitted, `T`imestamp, `N`OP, `W`indow-scale,
/// `E`OL, `?` for anything else). The ordering is an OS-discriminating signal.
fn option_layout(tcp: &TcpPacket) -> String {
    let mut layout = String::new();
    for opt in tcp.get_options_iter() {
        layout.push(match opt.get_number() {
            TcpOptionNumbers::MSS => 'M',
            TcpOptionNumbers::SACK_PERMITTED => 'S',
            TcpOptionNumbers::TIMESTAMPS => 'T',
            TcpOptionNumbers::NOP => 'N',
            TcpOptionNumbers::WSCALE => 'W',
            TcpOptionNumbers::EOL => 'E',
            _ => '?',
        });
    }
    layout
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

/// Build a TCP SYN segment with the fingerprint option set (no IP header — the
/// kernel prepends it on a raw TCP socket), checksum over the IPv4 pseudo-header.
pub fn build_syn_v4(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16, seq: u32) -> Vec<u8> {
    let mut buf = vec![0u8; SYN_LEN];
    let mut tcp = MutableTcpPacket::new(&mut buf).expect("SYN_LEN bytes");
    tcp.set_source(src_port);
    tcp.set_destination(dst_port);
    tcp.set_sequence(seq);
    tcp.set_data_offset((SYN_LEN / 4) as u8);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_window(DEFAULT_WINDOW);
    tcp.set_options(&syn_options());
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
            sig: StackSignature {
                ttl: Some(ip.get_ttl()),
                window: Some(tcp.get_window()),
                df: Some(ip.get_flags() & Ipv4Flags::DontFragment != 0),
                opts_layout: Some(option_layout(&tcp)),
            },
        },
    ))
}

// ---- IPv6 -----------------------------------------------------------------

/// Build a TCP SYN segment with the fingerprint option set, checksum over the
/// IPv6 pseudo-header.
pub fn build_syn_v6(src: Ipv6Addr, dst: Ipv6Addr, src_port: u16, dst_port: u16, seq: u32) -> Vec<u8> {
    let mut buf = vec![0u8; SYN_LEN];
    let mut tcp = MutableTcpPacket::new(&mut buf).expect("SYN_LEN bytes");
    tcp.set_source(src_port);
    tcp.set_destination(dst_port);
    tcp.set_sequence(seq);
    tcp.set_data_offset((SYN_LEN / 4) as u8);
    tcp.set_flags(TcpFlags::SYN);
    tcp.set_window(DEFAULT_WINDOW);
    tcp.set_options(&syn_options());
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
        sig: StackSignature {
            // No IP header on a raw IPv6 TCP socket, so TTL and DF are unavailable;
            // the window and option layout still come from the TCP segment.
            ttl: None,
            window: Some(tcp.get_window()),
            df: None,
            opts_layout: Some(option_layout(&tcp)),
        },
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
    fn syn_probe_carries_the_fingerprint_options() {
        // A bare SYN elicits only MSS in reply regardless of OS; our probe must
        // offer the full set so responders echo their own ordering (F-013).
        let buf = build_syn_v4(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 40000, 443, 1);
        let tcp = TcpPacket::new(&buf).unwrap();
        assert_eq!(tcp.get_data_offset(), 10, "20-byte header + 20 bytes of options");
        assert_eq!(option_layout(&tcp), "MSTNW");
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

    #[test]
    fn parses_stack_signature_from_synack() {
        use pnet::packet::tcp::TcpOption;
        // A Linux-style SYN-ACK option set: MSS, SACK-permitted, Timestamp, NOP,
        // Window-scale — 20 bytes, so the header is 40 bytes (data offset 10).
        let opts = [
            TcpOption::mss(1460),
            TcpOption::sack_perm(),
            TcpOption::timestamp(1, 0),
            TcpOption::nop(),
            TcpOption::wscale(7),
        ];
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 2);
        let synack = {
            let mut b = vec![0u8; 40];
            let mut tcp = MutableTcpPacket::new(&mut b).unwrap();
            tcp.set_source(22);
            tcp.set_destination(40000);
            tcp.set_data_offset(10);
            tcp.set_flags(TcpFlags::SYN | TcpFlags::ACK);
            tcp.set_window(64240);
            tcp.set_options(&opts);
            let cs = ipv4_checksum(&tcp.to_immutable(), &src, &dst);
            tcp.set_checksum(cs);
            b
        };
        // The option layout is read in order, one letter per option.
        assert_eq!(option_layout(&TcpPacket::new(&synack).unwrap()), "MSTNW");

        // Through the IP-header parse: layout, TTL, window and the DF bit.
        let mut ipbuf = vec![0u8; 20 + synack.len()];
        let mut ip = MutableIpv4Packet::new(&mut ipbuf).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((20 + synack.len()) as u16);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_flags(Ipv4Flags::DontFragment);
        ip.set_ttl(64);
        ip.set_source(src);
        ip.set_payload(&synack);

        let (_, reply) = parse_tcp_reply_v4(&ipbuf).unwrap();
        assert_eq!(reply.sig.opts_layout.as_deref(), Some("MSTNW"));
        assert_eq!(reply.sig.ttl, Some(64));
        assert_eq!(reply.sig.window, Some(64240));
        assert_eq!(reply.sig.df, Some(true));
    }
}
