//! Clean-room UDP service probes (F-002, C-001).
//!
//! Empty UDP datagrams only ever confirm *closed* (via ICMP) — most services need
//! a valid request before they answer. These payloads are minimal, well-formed
//! requests for common UDP protocols, so a live service replies and we can report
//! `Open` with real data instead of `open|filtered`.
//!
//! Every payload here is hand-constructed from the public protocol specification
//! (the relevant RFC / standard), **not** derived from Nmap's `nmap-payloads` or
//! any other licensed corpus — that entanglement is exactly what C-001 forbids.

/// DNS query for `version.bind` `TXT` in the `CHAOS` class — the classic server
/// version probe. Any DNS server replies (even to refuse), which confirms it is
/// live. (RFC 1035 wire format.)
pub const DNS_VERSION_BIND: &[u8] = &[
    0x13, 0x37, // transaction id
    0x01, 0x00, // flags: standard query, recursion desired
    0x00, 0x01, // qdcount = 1
    0x00, 0x00, // ancount
    0x00, 0x00, // nscount
    0x00, 0x00, // arcount
    0x07, b'v', b'e', b'r', b's', b'i', b'o', b'n', // "version"
    0x04, b'b', b'i', b'n', b'd', // "bind"
    0x00, // root label
    0x00, 0x10, // qtype = TXT
    0x00, 0x03, // qclass = CHAOS
];

/// NTP client request (mode 3): a 48-byte packet whose first byte encodes
/// LI=0, VN=3, Mode=3. Any NTP server replies with the time. (RFC 5905.)
pub static NTP_CLIENT: [u8; 48] = {
    let mut p = [0u8; 48];
    p[0] = 0x1b;
    p
};

/// SNMPv1 GetRequest for `sysDescr.0` (OID 1.3.6.1.2.1.1.1.0) with community
/// `public`. A reply confirms an SNMP agent and carries its system description.
/// (RFC 1157, BER-encoded by hand.)
pub const SNMP_GET_SYSDESCR: &[u8] = &[
    0x30, 0x26, // SEQUENCE, len 38
    0x02, 0x01, 0x00, // version = 0 (v1)
    0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // community = "public"
    0xa0, 0x19, // GetRequest PDU, len 25
    0x02, 0x01, 0x01, // request-id = 1
    0x02, 0x01, 0x00, // error-status = 0
    0x02, 0x01, 0x00, // error-index = 0
    0x30, 0x0e, // varbind list, len 14
    0x30, 0x0c, // varbind, len 12
    0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID 1.3.6.1.2.1.1.1.0
    0x05, 0x00, // value = NULL
];

/// SSDP `M-SEARCH` (UPnP discovery over HTTPU). Unicast to a host's port 1900;
/// UPnP devices reply with their device-description location. (UPnP Device
/// Architecture.)
pub const SSDP_MSEARCH: &[u8] = b"M-SEARCH * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
MAN: \"ssdp:discover\"\r\n\
MX: 1\r\n\
ST: ssdp:all\r\n\r\n";

/// mDNS service-enumeration query (`_services._dns-sd._udp.local` PTR). mDNS
/// responders reply with the services they advertise. (RFC 6762 / 6763.)
pub const MDNS_SERVICES: &[u8] = &[
    0x00, 0x00, // transaction id (0 for mDNS)
    0x00, 0x00, // flags: standard query
    0x00, 0x01, // qdcount = 1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // an/ns/ar
    0x09, b'_', b's', b'e', b'r', b'v', b'i', b'c', b'e', b's', // "_services"
    0x07, b'_', b'd', b'n', b's', b'-', b's', b'd', // "_dns-sd"
    0x04, b'_', b'u', b'd', b'p', // "_udp"
    0x05, b'l', b'o', b'c', b'a', b'l', // "local"
    0x00, // root label
    0x00, 0x0c, // qtype = PTR
    0x00, 0x01, // qclass = IN
];

/// The probe payload for a well-known UDP port, or an empty slice if we have none
/// (in which case the scan falls back to an empty datagram).
pub fn payload_for(port: u16) -> &'static [u8] {
    match port {
        53 => DNS_VERSION_BIND,
        123 => &NTP_CLIENT,
        161 => SNMP_GET_SYSDESCR,
        1900 => SSDP_MSEARCH,
        5353 => MDNS_SERVICES,
        _ => &[],
    }
}

/// A short protocol label for a port we have a probe for.
pub fn probe_name(port: u16) -> Option<&'static str> {
    match port {
        53 => Some("dns"),
        123 => Some("ntp"),
        161 => Some("snmp"),
        1900 => Some("ssdp"),
        5353 => Some("mdns"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ports_have_well_formed_payloads() {
        assert_eq!(&DNS_VERSION_BIND[0..2], &[0x13, 0x37], "DNS txn id");
        assert_eq!(NTP_CLIENT.len(), 48);
        assert_eq!(NTP_CLIENT[0], 0x1b, "NTP LI/VN/Mode byte");
        assert_eq!(SNMP_GET_SYSDESCR[0], 0x30, "SNMP is a BER SEQUENCE");
        assert_eq!(SNMP_GET_SYSDESCR.len(), 40);
        assert!(SSDP_MSEARCH.starts_with(b"M-SEARCH"));
        assert_eq!(&MDNS_SERVICES[12..14], &[0x09, b'_'], "mDNS first label length");
    }

    #[test]
    fn payload_lookup_matches_named_ports() {
        for port in [53u16, 123, 161, 1900, 5353] {
            assert!(!payload_for(port).is_empty());
            assert!(probe_name(port).is_some());
        }
        assert!(payload_for(40000).is_empty());
        assert!(probe_name(40000).is_none());
    }
}
