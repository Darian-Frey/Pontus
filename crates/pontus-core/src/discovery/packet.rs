//! Pure packet construction and parsing for the discovery probes.
//!
//! Everything here is I/O-free and deterministic, so it is unit-tested directly
//! (checksums, field round-trips). The async senders in the sibling modules build
//! on these functions; keeping the byte-level work isolated is what lets the
//! engine be trusted without a privileged socket in the loop.

use pnet::packet::{MutablePacket, Packet};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperation, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, checksum as icmp_checksum, echo_reply, echo_request};
use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::util::MacAddr;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A parsed ICMP echo reply, reduced to the fields discovery cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoReply {
    pub identifier: u16,
    pub sequence: u16,
}

// ---- ICMPv4 ---------------------------------------------------------------

/// Build an ICMPv4 echo request (type 8) with its checksum filled in.
pub fn build_echo_request_v4(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let len = echo_request::MutableEchoRequestPacket::minimum_packet_size() + payload.len();
    let mut buf = vec![0u8; len];
    let mut pkt = echo_request::MutableEchoRequestPacket::new(&mut buf).expect("buffer sized above");
    pkt.set_icmp_type(IcmpTypes::EchoRequest);
    pkt.set_sequence_number(seq);
    pkt.set_identifier(id);
    pkt.set_payload(payload);
    let cs = icmp_checksum(&IcmpPacket::new(pkt.packet()).expect("just built"));
    pkt.set_checksum(cs);
    buf
}

/// Parse a full datagram received on a raw IPv4 ICMP socket (which includes the
/// IPv4 header) into the source address and echo-reply fields, if it is one.
pub fn parse_icmp_reply_v4(buf: &[u8]) -> Option<(Ipv4Addr, EchoReply)> {
    let ip = Ipv4Packet::new(buf)?;
    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
        return None;
    }
    let reply = parse_echo_reply_v4(ip.payload())?;
    Some((ip.get_source(), reply))
}

/// Parse the ICMPv4 layer alone (no IP header) as an echo reply.
pub fn parse_echo_reply_v4(icmp: &[u8]) -> Option<EchoReply> {
    let hdr = IcmpPacket::new(icmp)?;
    if hdr.get_icmp_type() != IcmpTypes::EchoReply {
        return None;
    }
    let echo = echo_reply::EchoReplyPacket::new(icmp)?;
    Some(EchoReply { identifier: echo.get_identifier(), sequence: echo.get_sequence_number() })
}

// ---- ICMPv6 ---------------------------------------------------------------

/// Build an ICMPv6 echo request (type 128). The checksum is left zero: it depends
/// on the IPv6 pseudo-header, and the kernel computes it for us when the raw socket
/// has `IPV6_CHECKSUM` set (see [`super::icmp`]). [`icmpv6_checksum`] fills it in
/// for tests, where the addresses are known.
pub fn build_echo_request_v6(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    // ICMPv6 echo layout: type(1) code(1) checksum(2) id(2) seq(2) payload.
    let mut buf = vec![0u8; 8 + payload.len()];
    let mut pkt = MutableIcmpv6Packet::new(&mut buf).expect("buffer sized above");
    pkt.set_icmpv6_type(Icmpv6Types::EchoRequest);
    // Identifier/sequence live in the 4 bytes after the checksum.
    let body = pkt.payload_mut();
    body[0..2].copy_from_slice(&id.to_be_bytes());
    body[2..4].copy_from_slice(&seq.to_be_bytes());
    body[4..].copy_from_slice(payload);
    buf
}

/// Compute and write the ICMPv6 checksum for a buffer built by
/// [`build_echo_request_v6`], given the source and destination addresses.
pub fn icmpv6_checksum(buf: &mut [u8], src: Ipv6Addr, dst: Ipv6Addr) {
    let mut pkt = MutableIcmpv6Packet::new(buf).expect("caller owns a valid buffer");
    let cs = pnet::packet::icmpv6::checksum(&pkt.to_immutable(), &src, &dst);
    pkt.set_checksum(cs);
}

/// Parse an ICMPv6 datagram (no IP header — the kernel strips it on receive) as an
/// echo reply (type 129); the source comes from the socket address, not the packet.
pub fn parse_echo_reply_v6(icmp: &[u8]) -> Option<EchoReply> {
    if icmp.len() < 8 {
        return None;
    }
    let pkt = pnet::packet::icmpv6::Icmpv6Packet::new(icmp)?;
    if pkt.get_icmpv6_type() != Icmpv6Types::EchoReply {
        return None;
    }
    let body = pkt.payload();
    let identifier = u16::from_be_bytes([body[0], body[1]]);
    let sequence = u16::from_be_bytes([body[2], body[3]]);
    Some(EchoReply { identifier, sequence })
}

// ---- ARP ------------------------------------------------------------------

/// Build a complete Ethernet frame carrying an ARP "who-has `target_ip`" request,
/// broadcast from `sender_mac`/`sender_ip`. Returns the 42-byte frame.
pub fn build_arp_request(sender_mac: MacAddr, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    const ARP_LEN: usize = 28;
    let mut arp_buf = [0u8; ARP_LEN];
    let mut arp = MutableArpPacket::new(&mut arp_buf).expect("28 bytes");
    arp.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp.set_protocol_type(EtherTypes::Ipv4);
    arp.set_hw_addr_len(6);
    arp.set_proto_addr_len(4);
    arp.set_operation(ArpOperations::Request);
    arp.set_sender_hw_addr(sender_mac);
    arp.set_sender_proto_addr(sender_ip);
    arp.set_target_hw_addr(MacAddr::zero());
    arp.set_target_proto_addr(target_ip);

    let mut eth_buf = vec![0u8; 14 + ARP_LEN];
    let mut eth = MutableEthernetPacket::new(&mut eth_buf).expect("42 bytes");
    eth.set_destination(MacAddr::broadcast());
    eth.set_source(sender_mac);
    eth.set_ethertype(EtherTypes::Arp);
    eth.set_payload(arp.packet());
    eth_buf
}

/// Parse an Ethernet frame as an ARP reply, returning the responder's IP and MAC.
pub fn parse_arp_reply(frame: &[u8]) -> Option<(Ipv4Addr, MacAddr)> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    let arp = ArpPacket::new(eth.payload())?;
    if arp.get_operation() != ArpOperations::Reply {
        return None;
    }
    Some((arp.get_sender_proto_addr(), arp.get_sender_hw_addr()))
}

/// Read the ARP operation from a frame (test helper / introspection).
pub fn arp_operation(frame: &[u8]) -> Option<ArpOperation> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Arp {
        return None;
    }
    Some(ArpPacket::new(eth.payload())?.get_operation())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::arp::MutableArpPacket;
    use pnet::packet::ethernet::MutableEthernetPacket;

    #[test]
    fn icmpv4_echo_round_trips_and_checksum_is_valid() {
        let buf = build_echo_request_v4(0x1234, 7, b"pontus");
        // Checksum over a correct ICMP packet sums to zero.
        let pkt = IcmpPacket::new(&buf).unwrap();
        assert_eq!(icmp_checksum(&pkt), pkt.get_checksum());

        // The reply parser keys on type 0; flip the type byte and re-parse.
        let mut reply = buf.clone();
        reply[0] = 0; // EchoReply
        let parsed = parse_echo_reply_v4(&reply).unwrap();
        assert_eq!(parsed, EchoReply { identifier: 0x1234, sequence: 7 });
    }

    #[test]
    fn icmpv4_reply_unwraps_ip_header() {
        use pnet::packet::ipv4::MutableIpv4Packet;
        let icmp = {
            let mut b = build_echo_request_v4(0xABCD, 9, b"x");
            b[0] = 0; // EchoReply
            b
        };
        let mut ipbuf = vec![0u8; 20 + icmp.len()];
        let mut ip = MutableIpv4Packet::new(&mut ipbuf).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((20 + icmp.len()) as u16);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ip.set_source(Ipv4Addr::new(192, 168, 1, 42));
        ip.set_payload(&icmp);
        let (src, reply) = parse_icmp_reply_v4(&ipbuf).unwrap();
        assert_eq!(src, Ipv4Addr::new(192, 168, 1, 42));
        assert_eq!(reply.sequence, 9);
    }

    #[test]
    fn icmpv6_echo_fields_and_checksum() {
        let src = Ipv6Addr::LOCALHOST;
        let dst: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut buf = build_echo_request_v6(0x5566, 3, b"hi");
        icmpv6_checksum(&mut buf, src, dst);

        // Valid checksum re-verifies to itself.
        let pkt = pnet::packet::icmpv6::Icmpv6Packet::new(&buf).unwrap();
        assert_eq!(pnet::packet::icmpv6::checksum(&pkt, &src, &dst), pkt.get_checksum());

        buf[0] = 129; // EchoReply
        let parsed = parse_echo_reply_v6(&buf).unwrap();
        assert_eq!(parsed, EchoReply { identifier: 0x5566, sequence: 3 });
    }

    #[test]
    fn arp_request_is_well_formed() {
        let mac = MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0x00, 0x01);
        let frame = build_arp_request(mac, Ipv4Addr::new(192, 168, 1, 2), Ipv4Addr::new(192, 168, 1, 9));
        assert_eq!(frame.len(), 42);
        assert_eq!(arp_operation(&frame), Some(ArpOperations::Request));
        // A request is not a reply, so reply-parsing rejects it.
        assert!(parse_arp_reply(&frame).is_none());
    }

    #[test]
    fn arp_reply_parses_ip_and_mac() {
        let responder = MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66);
        let responder_ip = Ipv4Addr::new(192, 168, 1, 9);
        // Hand-build a reply frame.
        let mut arp_buf = [0u8; 28];
        let mut arp = MutableArpPacket::new(&mut arp_buf).unwrap();
        arp.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Reply);
        arp.set_sender_hw_addr(responder);
        arp.set_sender_proto_addr(responder_ip);
        arp.set_target_hw_addr(MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0, 1));
        arp.set_target_proto_addr(Ipv4Addr::new(192, 168, 1, 2));
        let mut eth_buf = vec![0u8; 42];
        let mut eth = MutableEthernetPacket::new(&mut eth_buf).unwrap();
        eth.set_destination(MacAddr::new(0xde, 0xad, 0xbe, 0xef, 0, 1));
        eth.set_source(responder);
        eth.set_ethertype(EtherTypes::Arp);
        eth.set_payload(arp.packet());

        let (ip, mac) = parse_arp_reply(&eth_buf).unwrap();
        assert_eq!(ip, responder_ip);
        assert_eq!(mac, responder);
    }
}
