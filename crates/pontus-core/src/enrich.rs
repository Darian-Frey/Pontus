//! Asset enrichment (F-027) — tag a public-IP asset with its ASN, network owner,
//! country and (where inferable) cloud provider.
//!
//! Data source is **Team Cymru's IP-to-ASN mapping over DNS** (`origin.asn.cymru.com`
//! / `asn.cymru.com` TXT records), queried via the user's own `dig` (D-006). No
//! dataset is vendored (C-001), and there's no MaxMind/GeoIP dependency — country
//! comes free from Cymru; city-level geo and full WHOIS are follow-ups. The cloud
//! provider is inferred clean-room from the ASN's network name.

use crate::error::Result;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::time::Duration;

/// Enrichment facts for one IP. All optional — a lookup may find nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Enrichment {
    pub asn: Option<u32>,
    pub asn_name: Option<String>,
    pub country: Option<String>,
    pub prefix: Option<String>,
    pub cloud: Option<String>,
}

impl Enrichment {
    /// True if the lookup found anything worth recording.
    pub fn is_empty(&self) -> bool {
        self.asn.is_none() && self.asn_name.is_none() && self.country.is_none() && self.cloud.is_none()
    }
}

/// Enrich a single IP. Private/loopback/reserved and IPv6 addresses return an
/// empty result (nothing to look up). IPv6 enrichment is a follow-up.
pub fn enrich_ip(ip: IpAddr, timeout: Duration) -> Result<Enrichment> {
    let IpAddr::V4(v4) = ip else {
        return Ok(Enrichment::default());
    };
    if !is_public(v4) {
        return Ok(Enrichment::default());
    }

    let mut e = Enrichment::default();
    let origin = format!("{}.origin.asn.cymru.com", reverse_ipv4(v4));
    if let Some(line) = dig_txt(&origin, timeout)?.into_iter().next() {
        if let Some((asn, prefix, country)) = parse_origin(&line) {
            e.asn = Some(asn);
            e.prefix = prefix;
            e.country = country;
        }
    }
    if let Some(asn) = e.asn {
        let name_q = format!("AS{asn}.asn.cymru.com");
        if let Some(line) = dig_txt(&name_q, timeout)?.into_iter().next() {
            if let Some(name) = parse_asname(&line) {
                e.cloud = infer_cloud(&name);
                e.asn_name = Some(name);
            }
        }
    }
    Ok(e)
}

/// Whether an IPv4 address is a routable, public address worth enriching.
pub fn is_public(a: Ipv4Addr) -> bool {
    let [b0, b1, ..] = a.octets();
    let cgnat = b0 == 100 && (0x40..=0x7f).contains(&b1); // 100.64.0.0/10
    !(a.is_private()
        || a.is_loopback()
        || a.is_link_local()
        || a.is_broadcast()
        || a.is_documentation()
        || a.is_unspecified()
        || a.is_multicast()
        || b0 == 0
        || cgnat)
}

/// `1.2.3.4` → `4.3.2.1` (the label order Cymru's origin zone expects).
fn reverse_ipv4(a: Ipv4Addr) -> String {
    let o = a.octets();
    format!("{}.{}.{}.{}", o[3], o[2], o[1], o[0])
}

/// Run `dig +short TXT <name>`, returning each TXT value with quotes stripped.
fn dig_txt(name: &str, timeout: Duration) -> Result<Vec<String>> {
    let secs = timeout.as_secs().max(1).to_string();
    let out = Command::new("dig")
        .args(["+short", &format!("+time={secs}"), "+tries=1", "TXT", name])
        .output()?; // dig missing → I/O error, surfaced to the caller
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().trim_matches('"').to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

/// Parse a Cymru origin TXT: `"<asn[ asn…]> | <prefix> | <country> | <registry> | <date>"`.
fn parse_origin(txt: &str) -> Option<(u32, Option<String>, Option<String>)> {
    let f: Vec<&str> = txt.split('|').map(str::trim).collect();
    // The ASN field can list several origins ("13335 174"); take the first.
    let asn = f.first()?.split_whitespace().next()?.parse::<u32>().ok()?;
    let prefix = f.get(1).filter(|s| !s.is_empty()).map(|s| s.to_string());
    let country = f.get(2).filter(|s| !s.is_empty()).map(|s| s.to_string());
    Some((asn, prefix, country))
}

/// Parse a Cymru ASN TXT: the network name is the last `|`-field.
fn parse_asname(txt: &str) -> Option<String> {
    let name = txt.rsplit('|').next()?.trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// Infer a cloud provider from an ASN network name (clean-room keyword map).
fn infer_cloud(asn_name: &str) -> Option<String> {
    let n = asn_name.to_ascii_uppercase();
    const MAP: &[(&str, &str)] = &[
        ("AMAZON", "AWS"),
        ("AWS", "AWS"),
        ("GOOGLE", "Google Cloud"),
        ("MICROSOFT", "Azure"),
        ("AZURE", "Azure"),
        ("DIGITALOCEAN", "DigitalOcean"),
        ("ORACLE", "Oracle Cloud"),
        ("CLOUDFLARE", "Cloudflare"),
        ("HETZNER", "Hetzner"),
        ("OVH", "OVH"),
        ("LINODE", "Linode/Akamai"),
        ("AKAMAI", "Linode/Akamai"),
        ("ALIBABA", "Alibaba Cloud"),
        ("ALICLOUD", "Alibaba Cloud"),
        ("VULTR", "Vultr"),
        ("CHOOPA", "Vultr"),
        ("SCALEWAY", "Scaleway"),
    ];
    MAP.iter().find(|(k, _)| n.contains(k)).map(|(_, v)| v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverses_ipv4_for_the_origin_zone() {
        assert_eq!(reverse_ipv4("1.2.3.4".parse().unwrap()), "4.3.2.1");
    }

    #[test]
    fn public_vs_private_classification() {
        let pub_ = |s: &str| is_public(s.parse().unwrap());
        assert!(pub_("1.1.1.1"));
        assert!(pub_("52.94.236.248"));
        assert!(!pub_("10.0.0.1"));
        assert!(!pub_("192.168.1.1"));
        assert!(!pub_("172.16.5.4"));
        assert!(!pub_("127.0.0.1"));
        assert!(!pub_("169.254.1.1"));
        assert!(!pub_("100.64.0.1")); // CGNAT
        assert!(!pub_("0.0.0.0"));
    }

    #[test]
    fn parses_cymru_origin_txt() {
        let (asn, prefix, country) =
            parse_origin("13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11").unwrap();
        assert_eq!(asn, 13335);
        assert_eq!(prefix.as_deref(), Some("1.1.1.0/24"));
        assert_eq!(country.as_deref(), Some("AU"));
        // Multi-origin: first ASN wins.
        assert_eq!(parse_origin("174 3356 | 8.0.0.0/9 | US | arin | x").unwrap().0, 174);
        assert!(parse_origin("garbage").is_none());
    }

    #[test]
    fn parses_asn_name_and_infers_cloud() {
        let name = parse_asname("13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US").unwrap();
        assert!(name.starts_with("CLOUDFLARENET"));
        assert_eq!(infer_cloud(&name).as_deref(), Some("Cloudflare"));
        assert_eq!(infer_cloud("AMAZON-02 - Amazon.com, Inc., US").as_deref(), Some("AWS"));
        assert_eq!(infer_cloud("GOOGLE - Google LLC, US").as_deref(), Some("Google Cloud"));
        assert_eq!(infer_cloud("MICROSOFT-CORP-MSN-AS-BLOCK, US").as_deref(), Some("Azure"));
        assert_eq!(infer_cloud("COMCAST-7922, US"), None); // a residential ISP, not a cloud
    }
}
