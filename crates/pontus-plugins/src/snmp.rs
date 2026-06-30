//! A minimal, clean-room SNMP v2c GET codec (BER) — just enough to read scalar
//! OIDs like `sysDescr.0` for the `snmp-info` plugin (F-021). Not a full SNMP
//! stack: single-varbind GET request, response value rendering for the common
//! types. No third-party SNMP/ASN.1 dependency (C-001).

// BER tags we use.
const T_INT: u8 = 0x02;
const T_OCTET: u8 = 0x04;
const T_NULL: u8 = 0x05;
const T_OID: u8 = 0x06;
const T_SEQ: u8 = 0x30;
const T_GET: u8 = 0xA0; // GetRequest-PDU
const T_RESPONSE: u8 = 0xA2; // GetResponse-PDU

/// Encode a BER length (short form, or long form for ≥128).
fn ber_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let mut bytes = Vec::new();
    let mut n = len;
    while n > 0 {
        bytes.insert(0, (n & 0xff) as u8);
        n >>= 8;
    }
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

/// Tag + length + content.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(ber_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Minimal big-endian two's-complement INTEGER (our values are non-negative).
fn ber_int(v: u32) -> Vec<u8> {
    let mut bytes = v.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0x00 && bytes[1] & 0x80 == 0 {
        bytes.remove(0);
    }
    // A leading bit set on a positive number needs a 0x00 sign byte.
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00);
    }
    tlv(T_INT, &bytes)
}

fn encode_base128(out: &mut Vec<u8>, mut v: u64) {
    let mut stack = [0u8; 10];
    let mut i = 0;
    stack[i] = (v & 0x7f) as u8;
    v >>= 7;
    while v > 0 {
        i += 1;
        stack[i] = (v & 0x7f) as u8 | 0x80;
        v >>= 7;
    }
    for j in (0..=i).rev() {
        out.push(stack[j]);
    }
}

fn ber_oid(arcs: &[u64]) -> Vec<u8> {
    let mut content = Vec::new();
    // First two arcs collapse into one byte-stream value.
    let first = arcs[0] * 40 + arcs[1];
    encode_base128(&mut content, first);
    for &a in &arcs[2..] {
        encode_base128(&mut content, a);
    }
    tlv(T_OID, &content)
}

/// Parse a dotted OID string (`1.3.6.1.2.1.1.1.0`) into arcs.
pub fn parse_oid(s: &str) -> Option<Vec<u64>> {
    let arcs: Option<Vec<u64>> = s.split('.').map(|p| p.parse().ok()).collect();
    let arcs = arcs?;
    if arcs.len() < 2 {
        return None;
    }
    Some(arcs)
}

/// Encode an SNMP v2c GetRequest for a single OID.
pub fn encode_get(community: &str, request_id: u32, oid: &[u64]) -> Vec<u8> {
    let varbind = tlv(T_SEQ, &[ber_oid(oid), tlv(T_NULL, &[])].concat());
    let varbinds = tlv(T_SEQ, &varbind);
    let pdu = tlv(
        T_GET,
        &[ber_int(request_id), ber_int(0), ber_int(0), varbinds].concat(),
    );
    let body = [ber_int(1), tlv(T_OCTET, community.as_bytes()), pdu].concat(); // version 1 = v2c
    tlv(T_SEQ, &body)
}

/// A BER cursor.
struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    /// Read one TLV, returning (tag, content) and the remaining bytes after it.
    fn read(&mut self) -> Option<(u8, &'a [u8])> {
        let data = self.data;
        if data.len() < 2 {
            return None;
        }
        let tag = data[0];
        let (len, header) = decode_len(&data[1..])?;
        let start = 1 + header;
        let end = start.checked_add(len)?;
        if end > data.len() {
            return None;
        }
        self.data = &data[end..];
        Some((tag, &data[start..end]))
    }
}

/// Decode a BER length; returns (length, bytes-consumed).
fn decode_len(data: &[u8]) -> Option<(usize, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 || data.len() < 1 + n {
        return None;
    }
    let mut len = 0usize;
    for &b in &data[1..1 + n] {
        len = (len << 8) | b as usize;
    }
    Some((len, 1 + n))
}

/// Parse an SNMP GetResponse and render the first varbind's value, or `None` if
/// the response is malformed, carries a non-zero error-status, or the value is a
/// no-such-object/instance/end-of-mib exception.
pub fn parse_get_response(pkt: &[u8]) -> Option<String> {
    let (tag, body) = Reader { data: pkt }.read()?;
    if tag != T_SEQ {
        return None;
    }
    let mut r = Reader { data: body };
    let _version = r.read()?;
    let _community = r.read()?;
    let (pdu_tag, pdu) = r.read()?;
    if pdu_tag != T_RESPONSE {
        return None;
    }
    let mut pr = Reader { data: pdu };
    let _req_id = pr.read()?;
    let (_, err_status) = pr.read()?;
    if err_status.first().copied().unwrap_or(0) != 0 {
        return None; // SNMP error-status set
    }
    let _err_index = pr.read()?;
    let (_, varbinds) = pr.read()?;
    let (_, varbind) = Reader { data: varbinds }.read()?;
    let mut vr = Reader { data: varbind };
    let _oid = vr.read()?;
    let (vtag, value) = vr.read()?;
    render_value(vtag, value)
}

fn render_value(tag: u8, value: &[u8]) -> Option<String> {
    match tag {
        T_OCTET => Some(String::from_utf8_lossy(value).trim().to_string()),
        T_INT | 0x41 | 0x42 | 0x43 => {
            // INTEGER / Counter32 / Gauge32 / TimeTicks — unsigned big-endian.
            let n = value.iter().fold(0u64, |acc, &b| (acc << 8) | b as u64);
            Some(n.to_string())
        }
        T_OID => {
            // Render an OID value back to dotted form (best-effort).
            let mut arcs = Vec::new();
            let mut iter = value.iter();
            if let Some(&first) = iter.next() {
                arcs.push((first / 40) as u64);
                arcs.push((first % 40) as u64);
            }
            let mut acc = 0u64;
            for &b in iter {
                acc = (acc << 7) | (b & 0x7f) as u64;
                if b & 0x80 == 0 {
                    arcs.push(acc);
                    acc = 0;
                }
            }
            Some(arcs.iter().map(|a| a.to_string()).collect::<Vec<_>>().join("."))
        }
        0x40 => Some(value.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(".")), // IpAddress
        0x80..=0x82 => None, // noSuchObject / noSuchInstance / endOfMibView
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dotted_oids() {
        assert_eq!(parse_oid("1.3.6.1.2.1.1.1.0").unwrap(), vec![1, 3, 6, 1, 2, 1, 1, 1, 0]);
        assert!(parse_oid("1").is_none());
        assert!(parse_oid("1.x").is_none());
    }

    #[test]
    fn encodes_a_well_formed_get() {
        let pkt = encode_get("public", 0x01020304, &parse_oid("1.3.6.1.2.1.1.1.0").unwrap());
        assert_eq!(pkt[0], T_SEQ);
        // version INTEGER(1), then the community string "public" must appear.
        assert!(pkt.windows(6).any(|w| w == b"public"));
        // The OID's first byte collapses 1.3 -> 0x2b.
        assert!(pkt.contains(&0x2b));
    }

    #[test]
    fn round_trips_through_a_hand_built_response() {
        // Build a GetResponse for sysDescr.0 = "Test Router" and parse it back.
        let oid = ber_oid(&parse_oid("1.3.6.1.2.1.1.1.0").unwrap());
        let val = tlv(T_OCTET, b"Test Router");
        let varbind = tlv(T_SEQ, &[oid, val].concat());
        let varbinds = tlv(T_SEQ, &varbind);
        let pdu = tlv(T_RESPONSE, &[ber_int(1), ber_int(0), ber_int(0), varbinds].concat());
        let msg = tlv(T_SEQ, &[ber_int(1), tlv(T_OCTET, b"public"), pdu].concat());
        assert_eq!(parse_get_response(&msg).as_deref(), Some("Test Router"));
    }

    #[test]
    fn error_status_and_exceptions_yield_none() {
        // error-status = 2 (noSuchName).
        let varbinds = tlv(T_SEQ, &[]);
        let pdu = tlv(T_RESPONSE, &[ber_int(1), ber_int(2), ber_int(0), varbinds].concat());
        let msg = tlv(T_SEQ, &[ber_int(1), tlv(T_OCTET, b"public"), pdu].concat());
        assert!(parse_get_response(&msg).is_none());

        // A varbind whose value is noSuchObject (0x80).
        let oid = ber_oid(&parse_oid("1.3.6.1.2.1.1.9.0").unwrap());
        let exc = tlv(0x80, &[]);
        let vb = tlv(T_SEQ, &tlv(T_SEQ, &[oid, exc].concat()));
        let pdu2 = tlv(T_RESPONSE, &[ber_int(1), ber_int(0), ber_int(0), vb].concat());
        let msg2 = tlv(T_SEQ, &[ber_int(1), tlv(T_OCTET, b"public"), pdu2].concat());
        assert!(parse_get_response(&msg2).is_none());
    }

    #[test]
    fn renders_a_long_octet_string_with_long_form_length() {
        let long = "A".repeat(200);
        let oid = ber_oid(&parse_oid("1.3.6.1.2.1.1.1.0").unwrap());
        let val = tlv(T_OCTET, long.as_bytes());
        let vb = tlv(T_SEQ, &tlv(T_SEQ, &[oid, val].concat()));
        let pdu = tlv(T_RESPONSE, &[ber_int(1), ber_int(0), ber_int(0), vb].concat());
        let msg = tlv(T_SEQ, &[ber_int(1), tlv(T_OCTET, b"public"), pdu].concat());
        assert_eq!(parse_get_response(&msg).as_deref(), Some(long.as_str()));
    }
}
