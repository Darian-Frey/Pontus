//! OS fingerprinting against an updatable, clean-room corpus (F-013).
//!
//! The guess is **family-level** (Linux/Unix, Windows, a BSD, network/embedded),
//! derived from passively-available signals rather than an active probe sequence:
//!
//! 1. **Initial TTL / hop limit** of a reply packet. Hosts start packets at a
//!    well-known TTL and each hop decrements it, so the *smallest* common initial
//!    TTL at or above the observed value identifies the origin's default: 64
//!    (Linux/Unix/macOS/BSD), 128 (Windows), 255 (much network gear). This is
//!    textbook IP behaviour, not data lifted from any fingerprint database.
//! 2. **TCP window size** advertised on the SYN-ACK — a weak refinement; the
//!    default corpus carries none and leaves it to community rules.
//! 3. **Service-banner OS tokens** the host *volunteers* — e.g. an SSH banner or
//!    HTTP `Server` header containing "Ubuntu", "Debian", "FreeBSD", "Win64".
//!
//! **Clean-room (C-001).** The built-in corpus is first-principles: the TTL
//! defaults are public IP-stack knowledge, and the banner tokens are matched
//! against strings the host itself emits. Nothing here is derived from
//! `nmap-os-db` or any other fingerprint corpus. The corpus is data, loadable and
//! extensible at runtime ([`OsCorpus::load`]) so it can be updated without a
//! rebuild — the community-updatable requirement of F-013.

use crate::error::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;

/// The passively-observed signals fed to [`fingerprint`].
#[derive(Debug, Clone, Default)]
pub struct OsSignals {
    /// TTL (IPv4) or hop limit of a reply packet, if one was captured raw.
    pub ttl: Option<u8>,
    /// TCP window advertised on the SYN-ACK, if captured.
    pub tcp_window: Option<u16>,
    /// IPv4 don't-fragment bit on the SYN-ACK, if captured.
    pub df: Option<bool>,
    /// TCP-option layout of the SYN-ACK, e.g. "MSTNW" — the strongest passive
    /// discriminator, since stacks order their options differently.
    pub opts_layout: Option<String>,
    /// Raw service banners the host volunteered (SSH, HTTP `Server`, …).
    pub banners: Vec<String>,
}

/// One corpus rule: a family attribution that fires when every condition it
/// specifies holds. A rule with no conditions never matches (so an empty or
/// malformed entry is inert rather than matching everything).
#[derive(Debug, Clone, Deserialize)]
pub struct OsRule {
    /// The OS family this rule attributes, e.g. "Linux/Unix", "Windows".
    pub family: String,
    /// Exact initial TTL (64 / 128 / 255) the observed TTL must round up to.
    #[serde(default)]
    pub initial_ttl: Option<u8>,
    /// Exact advertised TCP window.
    #[serde(default)]
    pub window: Option<u16>,
    /// Exact IPv4 don't-fragment bit.
    #[serde(default)]
    pub df: Option<bool>,
    /// Exact TCP-option layout, e.g. "MSTNW" (Linux) or "MNWNNS" (Windows).
    #[serde(default)]
    pub opts_layout: Option<String>,
    /// Case-insensitive substring that must appear in some banner.
    #[serde(default)]
    pub banner_substring: Option<String>,
    /// How much this rule contributes to its family's score. Defaults to 1.0.
    #[serde(default = "default_weight")]
    pub weight: f32,
    /// A human label for the evidence line and the stored detail, e.g. "Ubuntu".
    #[serde(default)]
    pub note: Option<String>,
}

fn default_weight() -> f32 {
    1.0
}

impl OsRule {
    fn conditions(&self) -> usize {
        self.initial_ttl.is_some() as usize
            + self.window.is_some() as usize
            + self.df.is_some() as usize
            + self.opts_layout.is_some() as usize
            + self.banner_substring.is_some() as usize
    }

    fn matches(&self, initial_ttl: Option<u8>, signals: &OsSignals, banners_lc: &[String]) -> bool {
        if self.conditions() == 0 {
            return false;
        }
        if let Some(t) = self.initial_ttl
            && initial_ttl != Some(t)
        {
            return false;
        }
        if let Some(w) = self.window
            && signals.tcp_window != Some(w)
        {
            return false;
        }
        if let Some(df) = self.df
            && signals.df != Some(df)
        {
            return false;
        }
        if let Some(layout) = &self.opts_layout
            && signals.opts_layout.as_deref() != Some(layout.as_str())
        {
            return false;
        }
        if let Some(sub) = &self.banner_substring {
            let sub = sub.to_lowercase();
            if !banners_lc.iter().any(|b| b.contains(&sub)) {
                return false;
            }
        }
        true
    }
}

/// A set of fingerprint rules. Use [`OsCorpus::builtin`] for the clean-room
/// defaults, or [`OsCorpus::load`] to layer a user file over them.
#[derive(Debug, Clone, Deserialize)]
pub struct OsCorpus {
    pub rules: Vec<OsRule>,
}

impl OsCorpus {
    /// The built-in clean-room corpus (see the module docs for provenance).
    pub fn builtin() -> Self {
        let blank = OsRule {
            family: String::new(),
            initial_ttl: None,
            window: None,
            df: None,
            opts_layout: None,
            banner_substring: None,
            weight: 1.0,
            note: None,
        };
        let mut rules = Vec::new();

        // Initial-TTL families — public IP-stack defaults, weak on their own (1.0).
        for &(ttl, family) in &[
            (64u8, "Linux/Unix"),
            (128u8, "Windows"),
            (255u8, "Network/Embedded"),
        ] {
            rules.push(OsRule {
                family: family.to_string(),
                initial_ttl: Some(ttl),
                ..blank.clone()
            });
        }

        // TCP-option layout of the SYN-ACK — the strongest passive discriminator,
        // since stacks order their options distinctively (p0f-style). Weighted
        // above TTL and banners (3.0). Layouts are public/first-principles, never
        // copied from a fingerprint database (C-001); extend via --os-corpus.
        // The family carries the OS; the layout shows up in the evidence line
        // ("TCP options …"), so these rules set no `note` (it would otherwise
        // double up as a redundant detail, e.g. "Linux/Unix (Linux)").
        for &(layout, family) in &[
            ("MSTNW", "Linux/Unix"),
            ("MSTN", "Linux/Unix"),
            ("MNWNNS", "Windows"),
            ("MNNS", "Windows"),
            ("MNWNNTSEE", "macOS"),
            ("MNWNNTS", "macOS"),
        ] {
            rules.push(OsRule {
                family: family.to_string(),
                opts_layout: Some(layout.to_string()),
                weight: 3.0,
                ..blank.clone()
            });
        }

        // Banner tokens the host volunteers — stronger than TTL (2.0).
        for &(sub, family, note) in &[
            ("ubuntu", "Linux/Unix", "Ubuntu"),
            ("debian", "Linux/Unix", "Debian"),
            ("raspbian", "Linux/Unix", "Raspberry Pi OS"),
            ("openwrt", "Linux/Unix", "OpenWrt"),
            ("centos", "Linux/Unix", "CentOS"),
            ("red hat", "Linux/Unix", "Red Hat"),
            ("fedora", "Linux/Unix", "Fedora"),
            ("freebsd", "FreeBSD", "FreeBSD"),
            ("openbsd", "OpenBSD", "OpenBSD"),
            ("netbsd", "NetBSD", "NetBSD"),
            ("darwin", "macOS", "macOS (Darwin)"),
            ("mac os", "macOS", "macOS"),
            ("win32", "Windows", "Windows"),
            ("win64", "Windows", "Windows"),
            ("microsoft-iis", "Windows", "Windows (IIS)"),
            ("mikrotik", "Network/Embedded", "MikroTik RouterOS"),
            ("routeros", "Network/Embedded", "MikroTik RouterOS"),
            ("cisco", "Network/Embedded", "Cisco"),
        ] {
            rules.push(OsRule {
                family: family.to_string(),
                banner_substring: Some(sub.to_string()),
                weight: 2.0,
                note: Some(note.to_string()),
                ..blank.clone()
            });
        }
        Self { rules }
    }

    /// Parse a corpus from JSON: `{ "rules": [ { "family": …, … }, … ] }`.
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }

    /// Append another corpus's rules to this one (user rules layer over builtins).
    pub fn extend(&mut self, other: OsCorpus) {
        self.rules.extend(other.rules);
    }

    /// The built-in corpus with the JSON file at `path` layered on top, so a site
    /// can add or override signatures without a rebuild (F-013 acceptance).
    pub fn load(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let mut corpus = Self::builtin();
        let json = std::fs::read_to_string(path)?;
        corpus.extend(Self::from_json(&json)?);
        Ok(corpus)
    }
}

/// A family-level OS attribution with the evidence behind it.
#[derive(Debug, Clone, PartialEq)]
pub struct OsGuess {
    pub family: String,
    /// A specific label where a banner pinned one, e.g. "Ubuntu".
    pub detail: Option<String>,
    /// How much to trust the guess, in `0.0..=1.0`: blends signal agreement with
    /// evidence strength, so a lone broad TTL match caps at 0.5 and only
    /// corroborating evidence (e.g. a matching banner) climbs higher.
    pub confidence: f32,
    /// Human-readable evidence lines for the winning family.
    pub evidence: Vec<String>,
}

impl OsGuess {
    /// A compact label for storage/display: "Linux/Unix (Ubuntu)", "Windows", or —
    /// when the detail already names the family (e.g. nmap's "Linux 5.0 - 5.4") —
    /// just the detail.
    pub fn label(&self) -> String {
        match &self.detail {
            Some(d) if d == &self.family => self.family.clone(),
            Some(d) if d.starts_with(&self.family) => d.clone(),
            Some(d) => format!("{} ({})", self.family, d),
            None => self.family.clone(),
        }
    }
}

/// Round an observed TTL up to the nearest common initial TTL (the packet started
/// there and lost one per hop).
fn initial_ttl(observed: u8) -> u8 {
    [64u8, 128, 255].into_iter().find(|&t| observed <= t).unwrap_or(255)
}

/// Attribute an OS family from passive signals against `corpus`, or `None` if no
/// rule matched. The winning family is the one with the most matched weight;
/// confidence is its share of all matched weight.
pub fn fingerprint(signals: &OsSignals, corpus: &OsCorpus) -> Option<OsGuess> {
    let initial = signals.ttl.map(initial_ttl);
    let banners_lc: Vec<String> = signals.banners.iter().map(|b| b.to_lowercase()).collect();

    let matched: Vec<&OsRule> = corpus
        .rules
        .iter()
        .filter(|r| r.matches(initial, signals, &banners_lc))
        .collect();
    if matched.is_empty() {
        return None;
    }

    let mut scores: HashMap<&str, f32> = HashMap::new();
    for r in &matched {
        *scores.entry(r.family.as_str()).or_default() += r.weight;
    }
    let total: f32 = scores.values().sum();
    // Pick the top family; ties break alphabetically for determinism.
    let family = scores
        .iter()
        .max_by(|a, b| a.1.total_cmp(b.1).then(b.0.cmp(a.0)))
        .map(|(f, _)| f.to_string())?;
    let best = scores[family.as_str()];

    // Confidence blends two things so a single broad signal never reads as
    // certainty: *agreement* (the winner's share of all matched weight, which
    // falls when signals point at different families) and *evidence strength*
    // (a saturating function of the winner's own weight, so one weak TTL match —
    // weight 1 — caps at 0.5, while a corroborating banner pushes it higher).
    let agreement = if total > 0.0 { best / total } else { 0.0 };
    let strength = best / (best + 1.0);
    let confidence = agreement * strength;

    let detail = matched
        .iter()
        .find(|r| r.family == family && r.note.is_some())
        .and_then(|r| r.note.clone());
    let evidence: Vec<String> = matched
        .iter()
        .filter(|r| r.family == family)
        .map(|r| describe(r))
        .collect();

    Some(OsGuess { family, detail, confidence, evidence })
}

/// A short evidence string for a matched rule.
fn describe(rule: &OsRule) -> String {
    if let Some(sub) = &rule.banner_substring {
        format!("banner contains \"{sub}\"")
    } else if let Some(layout) = &rule.opts_layout {
        format!("TCP options {layout}")
    } else if let Some(t) = rule.initial_ttl {
        format!("initial TTL {t}")
    } else if let Some(w) = rule.window {
        format!("TCP window {w}")
    } else if let Some(df) = rule.df {
        format!("DF {}", if df { "set" } else { "clear" })
    } else {
        rule.family.clone()
    }
}

/// Selects how a host's OS guess is produced (F-013, D-011): the default passive
/// corpus, or a shell-out to the user's own `nmap -O`.
pub trait OsDetector {
    /// Guess `host`'s OS. `signals` are the passively-captured stack/banner
    /// signals; an active backend may ignore them and probe the host itself.
    fn detect(&self, host: IpAddr, signals: &OsSignals) -> Option<OsGuess>;
}

/// The default detector: score passive `signals` against an [`OsCorpus`].
pub struct NativeOsDetector {
    corpus: OsCorpus,
}

impl NativeOsDetector {
    pub fn new(corpus: OsCorpus) -> Self {
        Self { corpus }
    }
}

impl OsDetector for NativeOsDetector {
    fn detect(&self, _host: IpAddr, signals: &OsSignals) -> Option<OsGuess> {
        fingerprint(signals, &self.corpus)
    }
}

/// Optional backend that shells out to the user's own `nmap -O` (D-011 option B,
/// mirroring the service `NmapDetector`/D-006). Never bundles or vendors Nmap, and
/// never reads `nmap-os-db` itself (C-001) — it only parses the verdict Nmap
/// prints. Returns `None` if nmap is absent, unprivileged (`-O` needs raw sockets,
/// so run via sudo), or makes no OS match, so the caller degrades gracefully.
pub struct NmapOsDetector {
    binary: String,
}

impl NmapOsDetector {
    pub fn new() -> Self {
        Self { binary: "nmap".to_string() }
    }

    pub fn with_binary(binary: impl Into<String>) -> Self {
        Self { binary: binary.into() }
    }
}

impl Default for NmapOsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl OsDetector for NmapOsDetector {
    fn detect(&self, host: IpAddr, _signals: &OsSignals) -> Option<OsGuess> {
        let output = std::process::Command::new(&self.binary)
            .args(["-O", "-Pn", "-oX", "-", &host.to_string()])
            .output()
            .ok()?;
        if !output.status.success() {
            return None; // nmap missing, unprivileged, or errored
        }
        parse_nmap_os(&String::from_utf8_lossy(&output.stdout))
    }
}

/// Parse the highest-accuracy `<osmatch>` from `nmap -oX` OS output into an
/// [`OsGuess`]. The osmatch name carries the version range (e.g. "Linux 5.0 -
/// 5.4"); the osclass gives the family.
fn parse_nmap_os(xml: &str) -> Option<OsGuess> {
    // nmap's XML carries a `<!DOCTYPE nmaprun>`, which roxmltree rejects unless DTDs
    // are explicitly allowed.
    let options = roxmltree::ParsingOptions { allow_dtd: true, ..Default::default() };
    let doc = roxmltree::Document::parse_with_options(xml, options).ok()?;

    let (name, accuracy, node) = doc
        .descendants()
        .filter(|n| n.has_tag_name("osmatch"))
        .filter_map(|m| {
            let name = m.attribute("name")?.to_string();
            let acc = m.attribute("accuracy").and_then(|a| a.parse::<f32>().ok()).unwrap_or(0.0);
            Some((name, acc, m))
        })
        .max_by(|a, b| a.1.total_cmp(&b.1))?;

    let osclass = node.descendants().find(|n| n.has_tag_name("osclass"));
    let family = osclass
        .and_then(|c| c.attribute("osfamily").or_else(|| c.attribute("vendor")))
        .filter(|s| !s.is_empty())
        .map_or_else(|| name.clone(), str::to_string);

    let mut evidence = vec!["nmap -O".to_string()];
    if let Some(cpe) = node.descendants().find(|n| n.has_tag_name("cpe")).and_then(|n| n.text()) {
        evidence.push(cpe.to_string());
    }

    Some(OsGuess { family, detail: Some(name), confidence: accuracy / 100.0, evidence })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals(ttl: Option<u8>, banners: &[&str]) -> OsSignals {
        OsSignals {
            ttl,
            banners: banners.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn ttl_64_buckets_to_linux() {
        let g = fingerprint(&signals(Some(64), &[]), &OsCorpus::builtin()).unwrap();
        assert_eq!(g.family, "Linux/Unix");
    }

    #[test]
    fn decremented_ttl_still_buckets_by_initial() {
        // 57 = 64 - 7 hops; 117 = 128 - 11 hops; 250 = 255 - 5 hops.
        let c = OsCorpus::builtin();
        assert_eq!(fingerprint(&signals(Some(57), &[]), &c).unwrap().family, "Linux/Unix");
        assert_eq!(fingerprint(&signals(Some(117), &[]), &c).unwrap().family, "Windows");
        assert_eq!(fingerprint(&signals(Some(250), &[]), &c).unwrap().family, "Network/Embedded");
    }

    #[test]
    fn ttl_only_is_a_weak_guess_not_certainty() {
        // TTL 64 only rules out Windows/old gear; a lone broad signal must not
        // read as certain. The saturating strength term caps it at 0.5.
        let g = fingerprint(&signals(Some(64), &[]), &OsCorpus::builtin()).unwrap();
        assert_eq!(g.family, "Linux/Unix");
        assert!(g.confidence <= 0.5, "TTL-only is weak evidence: {}", g.confidence);
    }

    #[test]
    fn banner_pins_a_distro_and_raises_confidence_above_ttl_only() {
        // TTL says generic Linux; the banner pins Ubuntu, corroborates the family,
        // and lifts confidence above what TTL alone would give.
        let ttl_only = fingerprint(&signals(Some(64), &[]), &OsCorpus::builtin()).unwrap();
        let g = fingerprint(&signals(Some(64), &["SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"]), &OsCorpus::builtin())
            .unwrap();
        assert_eq!(g.family, "Linux/Unix");
        assert_eq!(g.detail.as_deref(), Some("Ubuntu"));
        assert!(g.confidence > ttl_only.confidence,
                "corroborating banner beats TTL-only: {} vs {}", g.confidence, ttl_only.confidence);
    }

    #[test]
    fn tcp_option_layout_distinguishes_families_sharing_a_ttl() {
        let c = OsCorpus::builtin();
        // Both start at TTL 64, but the option layout separates Linux from macOS.
        let linux = fingerprint(
            &OsSignals { ttl: Some(64), opts_layout: Some("MSTNW".into()), ..Default::default() },
            &c,
        )
        .unwrap();
        assert_eq!(linux.family, "Linux/Unix");
        let mac = fingerprint(
            &OsSignals { ttl: Some(64), opts_layout: Some("MNWNNTSEE".into()), ..Default::default() },
            &c,
        )
        .unwrap();
        assert_eq!(mac.family, "macOS");
    }

    #[test]
    fn corroborating_stack_layout_beats_ttl_only_confidence() {
        let c = OsCorpus::builtin();
        let ttl_only = fingerprint(&signals(Some(64), &[]), &c).unwrap();
        let with_layout = fingerprint(
            &OsSignals { ttl: Some(64), opts_layout: Some("MSTNW".into()), ..Default::default() },
            &c,
        )
        .unwrap();
        assert_eq!(with_layout.family, "Linux/Unix");
        assert!(with_layout.confidence > ttl_only.confidence + 0.2,
                "the option layout should lift confidence well above TTL-only: {} vs {}",
                with_layout.confidence, ttl_only.confidence);
    }

    #[test]
    fn windows_stack_layout_with_its_ttl_is_high_confidence() {
        let g = fingerprint(
            &OsSignals { ttl: Some(128), opts_layout: Some("MNWNNS".into()), ..Default::default() },
            &OsCorpus::builtin(),
        )
        .unwrap();
        assert_eq!(g.family, "Windows");
        assert!(g.confidence > 0.7, "TTL and stack layout agree: {}", g.confidence);
    }

    #[test]
    fn windows_banner_overrides_a_linux_ttl() {
        // Contrived conflict: a 64 TTL but a Windows/IIS banner. The weighted
        // banner rule (2.0) beats the TTL rule (1.0).
        let g = fingerprint(&signals(Some(64), &["Server: Microsoft-IIS/10.0"]), &OsCorpus::builtin())
            .unwrap();
        assert_eq!(g.family, "Windows");
    }

    #[test]
    fn no_signals_no_guess() {
        assert!(fingerprint(&OsSignals::default(), &OsCorpus::builtin()).is_none());
        // A banner we don't recognise and no TTL yields nothing.
        assert!(fingerprint(&signals(None, &["bespoke-service/1.0"]), &OsCorpus::builtin()).is_none());
    }

    #[test]
    fn user_corpus_layers_over_builtin_without_a_rebuild() {
        let mut c = OsCorpus::builtin();
        c.extend(
            OsCorpus::from_json(
                r#"{ "rules": [ { "family": "Network/Embedded", "banner_substring": "dd-wrt", "note": "DD-WRT", "weight": 3.0 } ] }"#,
            )
            .unwrap(),
        );
        let g = fingerprint(&signals(Some(64), &["DD-WRT/v3 httpd"]), &c).unwrap();
        // The new rule (weight 3) beats the builtin Linux TTL rule (weight 1).
        assert_eq!(g.family, "Network/Embedded");
        assert_eq!(g.detail.as_deref(), Some("DD-WRT"));
    }

    #[test]
    fn label_formats_family_and_detail() {
        let g = OsGuess {
            family: "Linux/Unix".into(),
            detail: Some("Ubuntu".into()),
            confidence: 0.9,
            evidence: vec![],
        };
        assert_eq!(g.label(), "Linux/Unix (Ubuntu)");
        let g2 = OsGuess { detail: None, ..g };
        assert_eq!(g2.label(), "Linux/Unix");
        // A detail that already names the family (nmap's range) isn't doubled up.
        let g3 = OsGuess {
            family: "Linux".into(),
            detail: Some("Linux 5.0 - 5.4".into()),
            confidence: 0.95,
            evidence: vec![],
        };
        assert_eq!(g3.label(), "Linux 5.0 - 5.4");
    }

    #[test]
    fn parses_nmap_os_match() {
        let xml = r#"<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun>
<host>
<os>
<osmatch name="Linux 4.15 - 5.8" accuracy="92">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="4.X" accuracy="92"/>
</osmatch>
<osmatch name="Linux 5.0 - 5.4" accuracy="95">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X" accuracy="95">
<cpe>cpe:/o:linux:linux_kernel:5</cpe>
</osclass>
</osmatch>
</os>
</host>
</nmaprun>"#;
        let g = parse_nmap_os(xml).unwrap();
        // The highest-accuracy match wins.
        assert_eq!(g.family, "Linux");
        assert_eq!(g.detail.as_deref(), Some("Linux 5.0 - 5.4"));
        assert!((g.confidence - 0.95).abs() < 1e-6);
        assert!(g.evidence.iter().any(|e| e.contains("cpe:/o:linux")));
        assert_eq!(g.label(), "Linux 5.0 - 5.4");
    }

    #[test]
    fn nmap_os_output_without_a_match_is_none() {
        let xml = r#"<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun><host><os></os></host></nmaprun>"#;
        assert!(parse_nmap_os(xml).is_none());
    }
}
