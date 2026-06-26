//! TLS/SSL inspection (F-016): a clean-room, dependency-light prober.
//!
//! Rather than negotiate a secure session, this hand-rolls TLS `ClientHello`s and
//! parses the server's `ServerHello`/`Certificate` directly — the sslscan/testssl
//! technique — so it can observe what a real client never would: which *deprecated*
//! protocols and *weak* cipher suites a server still accepts, and the certificate
//! even when it is expired or self-signed. Only the X.509 parsing is delegated
//! (`x509-parser`); the TLS wire handling is ours, with no OpenSSL or crypto-stack
//! dependency, which keeps the engine pure-Rust and cross-platform (D-012).
//!
//! Scope: protocol enumeration SSLv3–TLS 1.3, certificate capture and inspection
//! via a TLS 1.2 handshake (the `Certificate` message is in the clear in ≤1.2),
//! and a weak-cipher acceptance probe. A TLS 1.3-only server encrypts its
//! certificate, so cert capture needs the server to also speak ≤1.2 (a documented
//! limitation, IMP follow-up).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

const REC_HANDSHAKE: u8 = 22;
const REC_ALERT: u8 = 21;
const HS_SERVER_HELLO: u8 = 2;
const HS_CERTIFICATE: u8 = 11;

/// A TLS protocol version we probe for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolVersion {
    Ssl3,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl ProtocolVersion {
    /// The 16-bit wire code (`0x0300`..=`0x0304`).
    pub fn code(self) -> u16 {
        match self {
            ProtocolVersion::Ssl3 => 0x0300,
            ProtocolVersion::Tls10 => 0x0301,
            ProtocolVersion::Tls11 => 0x0302,
            ProtocolVersion::Tls12 => 0x0303,
            ProtocolVersion::Tls13 => 0x0304,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ProtocolVersion::Ssl3 => "SSLv3",
            ProtocolVersion::Tls10 => "TLS 1.0",
            ProtocolVersion::Tls11 => "TLS 1.1",
            ProtocolVersion::Tls12 => "TLS 1.2",
            ProtocolVersion::Tls13 => "TLS 1.3",
        }
    }

    /// SSLv3/TLS 1.0/1.1 are deprecated (RFC 8996) and weak.
    pub fn is_deprecated(self) -> bool {
        matches!(self, ProtocolVersion::Ssl3 | ProtocolVersion::Tls10 | ProtocolVersion::Tls11)
    }

    /// Every version we enumerate, oldest first.
    pub fn all() -> [ProtocolVersion; 5] {
        [
            ProtocolVersion::Ssl3,
            ProtocolVersion::Tls10,
            ProtocolVersion::Tls11,
            ProtocolVersion::Tls12,
            ProtocolVersion::Tls13,
        ]
    }
}

/// A curated cipher-suite table: id → (name, weak?). Weak = RC4, 3DES/DES, NULL,
/// EXPORT, or anonymous (no authentication). Not exhaustive; enough to name what a
/// server selects and to assemble the offers below.
const CIPHERS: &[(u16, &str, bool)] = &[
    // TLS 1.3
    (0x1301, "TLS_AES_128_GCM_SHA256", false),
    (0x1302, "TLS_AES_256_GCM_SHA384", false),
    (0x1303, "TLS_CHACHA20_POLY1305_SHA256", false),
    // Strong TLS 1.2 AEAD
    (0xC02B, "ECDHE-ECDSA-AES128-GCM-SHA256", false),
    (0xC02F, "ECDHE-RSA-AES128-GCM-SHA256", false),
    (0xC02C, "ECDHE-ECDSA-AES256-GCM-SHA384", false),
    (0xC030, "ECDHE-RSA-AES256-GCM-SHA384", false),
    (0xCCA9, "ECDHE-ECDSA-CHACHA20-POLY1305", false),
    (0xCCA8, "ECDHE-RSA-CHACHA20-POLY1305", false),
    (0x009C, "RSA-AES128-GCM-SHA256", false),
    (0x009D, "RSA-AES256-GCM-SHA384", false),
    // Legacy-but-not-weak CBC (kept so old servers still answer a version probe)
    (0xC013, "ECDHE-RSA-AES128-SHA", false),
    (0xC014, "ECDHE-RSA-AES256-SHA", false),
    (0x002F, "RSA-AES128-SHA", false),
    (0x0035, "RSA-AES256-SHA", false),
    // Weak
    (0x0004, "RSA-RC4-128-MD5", true),
    (0x0005, "RSA-RC4-128-SHA", true),
    (0x000A, "RSA-3DES-EDE-CBC-SHA", true),
    (0x0016, "DHE-RSA-3DES-EDE-CBC-SHA", true),
    (0x0008, "RSA-DES40-CBC-SHA-EXPORT", true),
    (0x0009, "RSA-DES-CBC-SHA", true),
    (0x0001, "RSA-NULL-MD5", true),
    (0x0002, "RSA-NULL-SHA", true),
    (0x0018, "DH-anon-RC4-128-MD5", true),
    (0x001B, "DH-anon-3DES-EDE-CBC-SHA", true),
];

fn cipher_name(id: u16) -> String {
    CIPHERS
        .iter()
        .find(|(c, _, _)| *c == id)
        .map(|(_, n, _)| n.to_string())
        .unwrap_or_else(|| format!("0x{id:04X}"))
}

fn cipher_is_weak(id: u16) -> bool {
    CIPHERS.iter().find(|(c, _, _)| *c == id).map(|(_, _, w)| *w).unwrap_or(false)
}

fn all_cipher_ids() -> Vec<u16> {
    CIPHERS.iter().map(|(c, _, _)| *c).collect()
}

fn weak_cipher_ids() -> Vec<u16> {
    CIPHERS.iter().filter(|(_, _, w)| *w).map(|(c, _, _)| *c).collect()
}

/// Parsed details of the leaf certificate.
#[derive(Debug, Clone)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub sans: Vec<String>,
    /// Validity bounds as Unix timestamps.
    pub not_before: i64,
    pub not_after: i64,
    pub signature_algorithm: String,
    pub key_type: String,
    pub key_bits: Option<u32>,
    pub self_signed: bool,
}

/// Whether a probed protocol version is accepted, and the suite it selected.
#[derive(Debug, Clone)]
pub struct ProtocolSupport {
    pub version: ProtocolVersion,
    pub supported: bool,
    pub cipher: Option<String>,
}

/// A weakness flagged by inspection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    Expired,
    NotYetValid,
    ExpiringSoon(i64), // days remaining
    SelfSigned,
    WeakSignature(String),
    WeakKey(String),
    DeprecatedProtocol(ProtocolVersion),
    WeakCipher(String),
    HostnameMismatch(String),
    NoTls,
}

impl Finding {
    /// A one-line human description.
    pub fn describe(&self) -> String {
        match self {
            Finding::Expired => "certificate has expired".to_string(),
            Finding::NotYetValid => "certificate is not yet valid".to_string(),
            Finding::ExpiringSoon(d) => format!("certificate expires in {d} day(s)"),
            Finding::SelfSigned => "certificate is self-signed".to_string(),
            Finding::WeakSignature(a) => format!("weak certificate signature ({a})"),
            Finding::WeakKey(k) => format!("weak certificate key ({k})"),
            Finding::DeprecatedProtocol(v) => format!("deprecated protocol supported ({})", v.label()),
            Finding::WeakCipher(c) => format!("weak cipher suite accepted ({c})"),
            Finding::HostnameMismatch(h) => format!("certificate does not match host {h}"),
            Finding::NoTls => "no TLS service responded".to_string(),
        }
    }
}

/// The result of inspecting one TLS endpoint.
#[derive(Debug, Clone)]
pub struct TlsReport {
    pub protocols: Vec<ProtocolSupport>,
    pub cert: Option<CertInfo>,
    pub weak_ciphers: Vec<String>,
    pub findings: Vec<Finding>,
}

// ---- ClientHello construction ---------------------------------------------

fn u16_be(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

/// Length-prefix `body` with a `n`-byte big-endian length (n = 1, 2 or 3).
fn with_len(n: usize, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(n + body.len());
    let len = body.len();
    for i in (0..n).rev() {
        out.push((len >> (8 * i)) as u8);
    }
    out.extend_from_slice(body);
    out
}

fn sni_extension(host: &str) -> Vec<u8> {
    // server_name: list of (type=0 host_name, name). Skip for IP literals/empty.
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        return Vec::new();
    }
    let mut name = vec![0u8]; // name_type = host_name
    name.extend_from_slice(&with_len(2, host.as_bytes()));
    let list = with_len(2, &name);
    let mut ext = Vec::new();
    ext.extend_from_slice(&u16_be(0x0000)); // extension_type = server_name
    ext.extend_from_slice(&with_len(2, &list));
    ext
}

fn ext(extension_type: u16, body: &[u8]) -> Vec<u8> {
    let mut e = Vec::new();
    e.extend_from_slice(&u16_be(extension_type));
    e.extend_from_slice(&with_len(2, body));
    e
}

/// Build a ClientHello record offering `ciphers` at `version`. For a TLS 1.3
/// probe (`tls13`), the legacy version stays 1.2 and 1.3 is offered via the
/// supported_versions/key_share extensions.
fn client_hello(version: ProtocolVersion, ciphers: &[u16], sni: &str, tls13: bool) -> Vec<u8> {
    let legacy = if tls13 { 0x0303 } else { version.code() };

    let mut body = Vec::new();
    body.extend_from_slice(&u16_be(legacy)); // client_version
    body.extend_from_slice(&[0x50u8; 32]); // random (fixed; we never finish the handshake)
    body.extend_from_slice(&with_len(1, &[])); // session_id (empty)

    let mut cs = Vec::new();
    for c in ciphers {
        cs.extend_from_slice(&u16_be(*c));
    }
    body.extend_from_slice(&with_len(2, &cs)); // cipher_suites
    body.extend_from_slice(&with_len(1, &[0x00])); // compression: null

    // Extensions.
    let mut exts = Vec::new();
    exts.extend_from_slice(&sni_extension(sni));
    // supported_groups: x25519, secp256r1, secp384r1.
    exts.extend_from_slice(&ext(0x000a, &with_len(2, &[0x00, 0x1d, 0x00, 0x17, 0x00, 0x18])));
    // ec_point_formats: uncompressed.
    exts.extend_from_slice(&ext(0x000b, &with_len(1, &[0x00])));
    // signature_algorithms (broad enough for RSA/ECDSA with SHA-256/384/512/1).
    let sigalgs: &[u8] = &[
        0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05,
        0x01, 0x06, 0x01, 0x02, 0x01,
    ];
    exts.extend_from_slice(&ext(0x000d, &with_len(2, sigalgs)));
    if tls13 {
        // supported_versions: TLS 1.3, 1.2.
        exts.extend_from_slice(&ext(0x002b, &with_len(1, &[0x03, 0x04, 0x03, 0x03])));
        // key_share: x25519 with a fixed 32-byte value (detection only).
        let mut ks_entry = Vec::new();
        ks_entry.extend_from_slice(&u16_be(0x001d));
        ks_entry.extend_from_slice(&with_len(2, &[0x42u8; 32]));
        exts.extend_from_slice(&ext(0x0033, &with_len(2, &ks_entry)));
    }
    body.extend_from_slice(&with_len(2, &exts));

    // Wrap: Handshake(type=1) then record(type=22, version=legacy-or-1.0).
    let handshake = {
        let mut h = vec![0x01u8]; // client_hello
        h.extend_from_slice(&with_len(3, &body));
        h
    };
    let rec_version = if version == ProtocolVersion::Ssl3 { 0x0300 } else { 0x0301 };
    let mut record = vec![REC_HANDSHAKE];
    record.extend_from_slice(&u16_be(rec_version));
    record.extend_from_slice(&with_len(2, &handshake));
    record
}

// ---- Response parsing ------------------------------------------------------

/// Read one TLS record: `(content_type, payload)`.
fn read_record(stream: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr).ok()?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > 1 << 16 {
        return None;
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).ok()?;
    Some((hdr[0], payload))
}

/// Read the server's first flight: concatenated handshake bytes, and whether an
/// alert was seen (i.e. the offer was rejected).
fn read_first_flight(stream: &mut TcpStream) -> (Vec<u8>, bool) {
    let mut hs = Vec::new();
    let mut alert = false;
    for _ in 0..32 {
        match read_record(stream) {
            Some((REC_HANDSHAKE, p)) => hs.extend_from_slice(&p),
            Some((REC_ALERT, _)) => {
                alert = true;
                break;
            }
            Some(_) => {} // change_cipher_spec etc.
            None => break, // timeout or close — the flight is complete
        }
    }
    (hs, alert)
}

/// Split concatenated handshake bytes into `(msg_type, body)` messages.
fn handshake_messages(buf: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 4 <= buf.len() {
        let mtype = buf[i];
        let len = ((buf[i + 1] as usize) << 16) | ((buf[i + 2] as usize) << 8) | buf[i + 3] as usize;
        let start = i + 4;
        let end = start + len;
        if end > buf.len() {
            break;
        }
        out.push((mtype, &buf[start..end]));
        i = end;
    }
    out
}

/// Parse a ServerHello body into `(negotiated_version, cipher_suite)`. The real
/// version may be carried in a supported_versions extension (TLS 1.3).
fn parse_server_hello(body: &[u8]) -> Option<(u16, u16)> {
    if body.len() < 2 + 32 + 1 {
        return None;
    }
    let legacy_version = u16::from_be_bytes([body[0], body[1]]);
    let mut i = 2 + 32; // skip version + random
    let sid_len = *body.get(i)? as usize;
    i += 1 + sid_len;
    let cipher = u16::from_be_bytes([*body.get(i)?, *body.get(i + 1)?]);
    i += 2;
    i += 1; // compression method
    let mut version = legacy_version;
    // Optional extensions: look for supported_versions (0x002b).
    if i + 2 <= body.len() {
        let ext_total = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2;
        let end = (i + ext_total).min(body.len());
        while i + 4 <= end {
            let etype = u16::from_be_bytes([body[i], body[i + 1]]);
            let elen = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
            let estart = i + 4;
            if estart + elen > end {
                break;
            }
            if etype == 0x002b && elen >= 2 {
                version = u16::from_be_bytes([body[estart], body[estart + 1]]);
            }
            i = estart + elen;
        }
    }
    Some((version, cipher))
}

/// Extract the DER certificates from a TLS ≤1.2 Certificate handshake message.
fn parse_certificates(body: &[u8]) -> Vec<Vec<u8>> {
    let mut certs = Vec::new();
    if body.len() < 3 {
        return certs;
    }
    let list_len = ((body[0] as usize) << 16) | ((body[1] as usize) << 8) | body[2] as usize;
    let mut i = 3;
    let end = (3 + list_len).min(body.len());
    while i + 3 <= end {
        let clen = ((body[i] as usize) << 16) | ((body[i + 1] as usize) << 8) | body[i + 2] as usize;
        let start = i + 3;
        if start + clen > end {
            break;
        }
        certs.push(body[start..start + clen].to_vec());
        i = start + clen;
    }
    certs
}

// ---- Probing ---------------------------------------------------------------

struct Handshake {
    version: Option<u16>,
    cipher: Option<u16>,
    certs: Vec<Vec<u8>>,
    alert: bool,
}

/// Send one ClientHello and parse the server's reply.
fn do_handshake(addr: SocketAddr, hello: &[u8], timeout: Duration) -> Option<Handshake> {
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    stream.write_all(hello).ok()?;
    let (hs, alert) = read_first_flight(&mut stream);

    let mut out = Handshake { version: None, cipher: None, certs: Vec::new(), alert };
    for (mtype, body) in handshake_messages(&hs) {
        match mtype {
            HS_SERVER_HELLO => {
                if let Some((v, c)) = parse_server_hello(body) {
                    out.version = Some(v);
                    out.cipher = Some(c);
                }
            }
            HS_CERTIFICATE => out.certs = parse_certificates(body),
            _ => {}
        }
    }
    Some(out)
}

/// Probe whether `version` is accepted, returning the selected cipher and any
/// certificates the server offered (≤1.2 only).
fn probe_version(
    addr: SocketAddr,
    sni: &str,
    version: ProtocolVersion,
    timeout: Duration,
) -> (bool, Option<u16>, Vec<Vec<u8>>) {
    let tls13 = version == ProtocolVersion::Tls13;
    let hello = client_hello(version, &all_cipher_ids(), sni, tls13);
    let Some(hs) = do_handshake(addr, &hello, timeout) else {
        return (false, None, Vec::new());
    };
    if hs.alert {
        return (false, None, hs.certs);
    }
    let accepted = hs.version == Some(version.code());
    (accepted, hs.cipher, hs.certs)
}

/// Inspect a TLS endpoint (F-016): enumerate protocols, capture and inspect the
/// certificate, probe for weak-cipher acceptance, and derive findings.
pub fn inspect(addr: SocketAddr, sni: &str, timeout: Duration) -> TlsReport {
    let mut protocols = Vec::new();
    let mut captured_certs: Vec<Vec<u8>> = Vec::new();
    let mut any = false;

    for version in ProtocolVersion::all() {
        let (supported, cipher, certs) = probe_version(addr, sni, version, timeout);
        if supported {
            any = true;
            if captured_certs.is_empty() && !certs.is_empty() {
                captured_certs = certs;
            }
        }
        protocols.push(ProtocolSupport {
            version,
            supported,
            cipher: cipher.filter(|_| supported).map(cipher_name),
        });
    }

    // Weak-cipher acceptance: offer only weak suites at TLS 1.2.
    let mut weak_ciphers = Vec::new();
    let weak_hello = client_hello(ProtocolVersion::Tls12, &weak_cipher_ids(), sni, false);
    if let Some(hs) = do_handshake(addr, &weak_hello, timeout)
        && !hs.alert
        && let Some(c) = hs.cipher
        && cipher_is_weak(c)
    {
        weak_ciphers.push(cipher_name(c));
    }

    let cert = captured_certs.first().and_then(|der| parse_cert(der));
    let findings = derive_findings(&protocols, &weak_ciphers, cert.as_ref(), sni, any);

    TlsReport { protocols, cert, weak_ciphers, findings }
}

// ---- Certificate parsing & findings ---------------------------------------

fn parse_cert(der: &[u8]) -> Option<CertInfo> {
    use x509_parser::prelude::*;
    use x509_parser::public_key::PublicKey;
    let (_, cert) = X509Certificate::from_der(der).ok()?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    let self_signed = subject == issuer;

    let sans = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|gn| match gn {
                    GeneralName::DNSName(n) => Some((*n).to_string()),
                    GeneralName::IPAddress(b) => Some(format!("IP:{}", hex_ip(b))),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    let signature_algorithm = sig_alg_name(&cert.signature_algorithm.algorithm.to_id_string());

    let (key_type, key_bits) = match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            let bits = (rsa.key_size() * 8) as u32;
            ("RSA".to_string(), Some(bits))
        }
        Ok(PublicKey::EC(ec)) => ("EC".to_string(), Some((ec.key_size()) as u32)),
        Ok(_) => ("other".to_string(), None),
        Err(_) => ("unknown".to_string(), None),
    };

    Some(CertInfo {
        subject,
        issuer,
        sans,
        not_before,
        not_after,
        signature_algorithm,
        key_type,
        key_bits,
        self_signed,
    })
}

fn hex_ip(b: &[u8]) -> String {
    match b.len() {
        4 => format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]),
        16 => b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":"),
        _ => "?".to_string(),
    }
}

/// Map a signature-algorithm OID string to a friendly, weakness-revealing name.
fn sig_alg_name(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.4" => "md5WithRSA".to_string(),
        "1.2.840.113549.1.1.5" => "sha1WithRSA".to_string(),
        "1.2.840.113549.1.1.11" => "sha256WithRSA".to_string(),
        "1.2.840.113549.1.1.12" => "sha384WithRSA".to_string(),
        "1.2.840.113549.1.1.13" => "sha512WithRSA".to_string(),
        "1.2.840.10045.4.1" => "ecdsaWithSHA1".to_string(),
        "1.2.840.10045.4.3.2" => "ecdsaWithSHA256".to_string(),
        "1.2.840.10045.4.3.3" => "ecdsaWithSHA384".to_string(),
        other => other.to_string(),
    }
}

fn sig_alg_is_weak(name: &str) -> bool {
    let n = name.to_lowercase();
    n.contains("md5") || n.contains("sha1")
}

/// Does `host` match the cert's SANs (or, failing SANs, its subject)?
fn hostname_matches(host: &str, cert: &CertInfo) -> bool {
    if host.is_empty() || host.parse::<std::net::IpAddr>().is_ok() {
        return true; // can't meaningfully name-check an IP literal here
    }
    let host = host.to_lowercase();
    let names: Vec<String> = if cert.sans.is_empty() {
        cert.subject
            .split(',')
            .filter_map(|p| p.trim().strip_prefix("CN="))
            .map(|s| s.to_string())
            .collect()
    } else {
        cert.sans.iter().filter(|s| !s.starts_with("IP:")).cloned().collect()
    };
    names.iter().any(|n| name_matches(&n.to_lowercase(), &host))
}

/// Match a DNS name against a (possibly wildcard) certificate name.
fn name_matches(pattern: &str, host: &str) -> bool {
    if let Some(rest) = pattern.strip_prefix("*.") {
        // A wildcard matches exactly one left-most label.
        host.split_once('.').map(|(_, tail)| tail == rest).unwrap_or(false)
    } else {
        pattern == host
    }
}

fn derive_findings(
    protocols: &[ProtocolSupport],
    weak_ciphers: &[String],
    cert: Option<&CertInfo>,
    sni: &str,
    any_tls: bool,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !any_tls {
        findings.push(Finding::NoTls);
        return findings;
    }
    for p in protocols {
        if p.supported && p.version.is_deprecated() {
            findings.push(Finding::DeprecatedProtocol(p.version));
        }
    }
    for c in weak_ciphers {
        findings.push(Finding::WeakCipher(c.clone()));
    }
    if let Some(cert) = cert {
        let now = chrono::Utc::now().timestamp();
        if now > cert.not_after {
            findings.push(Finding::Expired);
        } else {
            let days = (cert.not_after - now) / 86_400;
            if days < 30 {
                findings.push(Finding::ExpiringSoon(days));
            }
        }
        if now < cert.not_before {
            findings.push(Finding::NotYetValid);
        }
        if cert.self_signed {
            findings.push(Finding::SelfSigned);
        }
        if sig_alg_is_weak(&cert.signature_algorithm) {
            findings.push(Finding::WeakSignature(cert.signature_algorithm.clone()));
        }
        if cert.key_type == "RSA" && cert.key_bits.is_some_and(|b| b < 2048) {
            findings.push(Finding::WeakKey(format!("RSA {}", cert.key_bits.unwrap())));
        }
        if !hostname_matches(sni, cert) {
            findings.push(Finding::HostnameMismatch(sni.to_string()));
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_hello_is_well_formed() {
        let h = client_hello(ProtocolVersion::Tls12, &[0xC02F, 0x002F], "example.com", false);
        assert_eq!(h[0], REC_HANDSHAKE);
        // Record length matches the trailing bytes.
        let rec_len = u16::from_be_bytes([h[3], h[4]]) as usize;
        assert_eq!(rec_len, h.len() - 5);
        // Handshake message type is client_hello.
        assert_eq!(h[5], 0x01);
        let hs_len = ((h[6] as usize) << 16) | ((h[7] as usize) << 8) | h[8] as usize;
        assert_eq!(hs_len, h.len() - 9);
    }

    #[test]
    fn tls13_probe_sets_supported_versions() {
        let h = client_hello(ProtocolVersion::Tls13, &[0x1301], "h", true);
        // The legacy client_version is 1.2; 1.3 rides in supported_versions (0x002b).
        assert_eq!(&h[5 + 4..5 + 4 + 2], &[0x03, 0x03]);
        assert!(h.windows(2).any(|w| w == [0x00, 0x2b]), "supported_versions present");
        assert!(h.windows(2).any(|w| w == [0x00, 0x33]), "key_share present");
    }

    #[test]
    fn parses_a_synthetic_server_hello() {
        // version 1.2, 32-byte random, empty session id, cipher 0xC02F, null compression.
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // session id len
        body.extend_from_slice(&[0xC0, 0x2F]);
        body.push(0); // compression
        let (v, c) = parse_server_hello(&body).unwrap();
        assert_eq!(v, 0x0303);
        assert_eq!(c, 0xC02F);
    }

    #[test]
    fn server_hello_supported_versions_overrides_legacy() {
        // legacy 1.2 but a supported_versions extension announcing 1.3.
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0x13, 0x01]); // cipher
        body.push(0); // compression
        let ext = [0x00u8, 0x2b, 0x00, 0x02, 0x03, 0x04];
        body.extend_from_slice(&u16_be(ext.len() as u16));
        body.extend_from_slice(&ext);
        let (v, _) = parse_server_hello(&body).unwrap();
        assert_eq!(v, 0x0304, "negotiated TLS 1.3 via supported_versions");
    }

    #[test]
    fn parses_a_certificate_message() {
        let cert_a = [0xAAu8; 4];
        let cert_b = [0xBBu8; 6];
        let mut body = Vec::new();
        let mut list = Vec::new();
        list.extend_from_slice(&with_len(3, &cert_a));
        list.extend_from_slice(&with_len(3, &cert_b));
        body.extend_from_slice(&with_len(3, &list));
        let certs = parse_certificates(&body);
        assert_eq!(certs, vec![cert_a.to_vec(), cert_b.to_vec()]);
    }

    #[test]
    fn wildcard_name_matching() {
        assert!(name_matches("*.example.com", "www.example.com"));
        assert!(!name_matches("*.example.com", "example.com"));
        assert!(!name_matches("*.example.com", "a.b.example.com"));
        assert!(name_matches("example.com", "example.com"));
    }

    #[test]
    fn weak_classification() {
        assert!(cipher_is_weak(0x000A)); // 3DES
        assert!(cipher_is_weak(0x0005)); // RC4
        assert!(!cipher_is_weak(0xC02F)); // ECDHE-RSA-AES128-GCM
        assert!(sig_alg_is_weak("sha1WithRSA"));
        assert!(!sig_alg_is_weak("sha256WithRSA"));
        assert!(ProtocolVersion::Tls10.is_deprecated());
        assert!(!ProtocolVersion::Tls12.is_deprecated());
    }
}
