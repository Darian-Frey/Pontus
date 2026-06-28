//! Alert rules over scan drift (F-019).
//!
//! An alert is a *change*, not a state: rules are evaluated against the [`HostDiff`]
//! set produced by comparing two scans (`diff::diff_observations`). Because a diff
//! reports a change exactly once — port 22 shows up in `opened` on the scan it
//! opens and never again while it stays open — change-triggered rules fire exactly
//! once without the module having to remember what it has already alerted on. This
//! is the headless matching logic; delivery (log/desktop/webhook/Slack/Discord)
//! lives in the daemon, which owns the runtime and the I/O.

use crate::diff::{HostDiff, HostStatus, PortRef};
use serde::{Deserialize, Serialize};

/// The kind of change a rule fires on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Condition {
    /// A port opened on a host (optionally filtered to a specific port/proto).
    PortOpened,
    /// A port closed on a host (optionally filtered to a specific port/proto).
    PortClosed,
    /// A host appeared that was absent from the earlier scan.
    HostNew,
    /// A host present in the earlier scan is now gone.
    HostVanished,
    /// A host present in both scans changed (ports and/or address).
    HostChanged,
    /// A host kept its identity but moved to a new IP (the C-003 case).
    AddressMoved,
}

/// One alert rule: a condition, optional port/proto filter, and the channels to
/// deliver matches to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub name: String,
    pub condition: Condition,
    /// Restrict port conditions to this port; `None` matches any port.
    pub port: Option<u16>,
    /// Restrict port conditions to this protocol (case-insensitive); `None` = any.
    pub proto: Option<String>,
    /// Channel names this rule delivers to (interpreted by the daemon).
    pub channels: Vec<String>,
}

/// A fired alert — one matched change, carrying the channels to deliver it to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Alert {
    pub rule: String,
    pub summary: String,
    pub asset_id: i64,
    /// `kind=value`, e.g. `mac=aa:bb:…` — the durable identity, not just the IP.
    pub identity: String,
    pub ip: String,
    pub channels: Vec<String>,
}

/// Evaluate every rule against every host diff, returning all fired alerts in a
/// stable order (host by host, rule by rule).
pub fn evaluate(rules: &[Rule], diffs: &[HostDiff]) -> Vec<Alert> {
    let mut out = Vec::new();
    for d in diffs {
        for r in rules {
            out.extend(matches(r, d));
        }
    }
    out
}

fn matches(rule: &Rule, d: &HostDiff) -> Vec<Alert> {
    let mk = |summary: String| Alert {
        rule: rule.name.clone(),
        summary,
        asset_id: d.asset_id,
        identity: format!("{}={}", d.identity_kind, d.identity_value),
        ip: d.ip.clone(),
        channels: rule.channels.clone(),
    };
    let id = &d.identity_value;
    let port_match = |p: &PortRef| {
        rule.port.is_none_or(|rp| rp == p.port)
            && rule
                .proto
                .as_deref()
                .is_none_or(|rp| rp.eq_ignore_ascii_case(&p.proto))
    };
    match rule.condition {
        Condition::PortOpened => d
            .opened
            .iter()
            .filter(|p| port_match(p))
            .map(|p| mk(format!("port {p} opened on {id} ({})", d.ip)))
            .collect(),
        Condition::PortClosed => d
            .closed
            .iter()
            .filter(|p| port_match(p))
            .map(|p| mk(format!("port {p} closed on {id} ({})", d.ip)))
            .collect(),
        Condition::HostNew => (d.status == HostStatus::New)
            .then(|| mk(format!("new host {id} ({})", d.ip)))
            .into_iter()
            .collect(),
        Condition::HostVanished => (d.status == HostStatus::Vanished)
            .then(|| mk(format!("host vanished: {id} (last seen {})", d.ip)))
            .into_iter()
            .collect(),
        Condition::HostChanged => (d.status == HostStatus::Changed)
            .then(|| mk(format!("host changed: {id} ({})", d.ip)))
            .into_iter()
            .collect(),
        Condition::AddressMoved => d
            .moved_from
            .as_ref()
            .map(|from| mk(format!("{id} moved {from} → {}", d.ip)))
            .into_iter()
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diff(status: HostStatus, opened: &[(&str, u16)], closed: &[(&str, u16)], moved_from: Option<&str>) -> HostDiff {
        let pr = |(proto, port): &(&str, u16)| PortRef { proto: proto.to_string(), port: *port };
        HostDiff {
            asset_id: 1,
            identity_kind: "mac".into(),
            identity_value: "aa:bb:cc:dd:ee:ff".into(),
            ip: "192.168.1.10".into(),
            status,
            opened: opened.iter().map(pr).collect(),
            closed: closed.iter().map(pr).collect(),
            moved_from: moved_from.map(str::to_string),
        }
    }

    fn rule(condition: Condition, port: Option<u16>, proto: Option<&str>) -> Rule {
        Rule {
            name: "r".into(),
            condition,
            port,
            proto: proto.map(str::to_string),
            channels: vec!["log".into()],
        }
    }

    #[test]
    fn port_opened_with_a_specific_port_fires_exactly_once() {
        let d = diff(HostStatus::Changed, &[("tcp", 22), ("tcp", 80)], &[], None);
        let alerts = evaluate(&[rule(Condition::PortOpened, Some(22), None)], &[d]);
        assert_eq!(alerts.len(), 1, "exactly one alert for the one matching port (F-019 acceptance)");
        assert!(alerts[0].summary.contains("port tcp/22 opened"));
        assert_eq!(alerts[0].channels, vec!["log"]);
    }

    #[test]
    fn port_filter_respects_protocol() {
        let d = diff(HostStatus::Changed, &[("udp", 53)], &[], None);
        let tcp = evaluate(&[rule(Condition::PortOpened, Some(53), Some("tcp"))], std::slice::from_ref(&d));
        let udp = evaluate(&[rule(Condition::PortOpened, Some(53), Some("udp"))], &[d]);
        assert!(tcp.is_empty(), "tcp/53 rule must not match udp/53");
        assert_eq!(udp.len(), 1);
    }

    #[test]
    fn any_port_rule_fires_per_opened_port() {
        let d = diff(HostStatus::Changed, &[("tcp", 22), ("tcp", 443)], &[], None);
        let alerts = evaluate(&[rule(Condition::PortOpened, None, None)], &[d]);
        assert_eq!(alerts.len(), 2);
    }

    #[test]
    fn host_lifecycle_and_move_conditions() {
        let new = diff(HostStatus::New, &[("tcp", 22)], &[], None);
        let gone = diff(HostStatus::Vanished, &[], &[("tcp", 22)], None);
        let moved = diff(HostStatus::Changed, &[], &[], Some("192.168.1.9"));

        assert_eq!(evaluate(&[rule(Condition::HostNew, None, None)], std::slice::from_ref(&new)).len(), 1);
        assert!(evaluate(&[rule(Condition::HostNew, None, None)], std::slice::from_ref(&gone)).is_empty());
        assert_eq!(evaluate(&[rule(Condition::HostVanished, None, None)], &[gone]).len(), 1);
        assert_eq!(evaluate(&[rule(Condition::AddressMoved, None, None)], std::slice::from_ref(&moved)).len(), 1);
        assert!(evaluate(&[rule(Condition::AddressMoved, None, None)], &[new]).is_empty());
    }

    #[test]
    fn unchanged_host_fires_nothing() {
        let d = diff(HostStatus::Unchanged, &[], &[], None);
        let rules = [
            rule(Condition::PortOpened, None, None),
            rule(Condition::HostChanged, None, None),
            rule(Condition::HostNew, None, None),
        ];
        assert!(evaluate(&rules, &[d]).is_empty());
    }

    #[test]
    fn condition_deserialises_from_snake_case() {
        let c: Condition = serde_json::from_str("\"port_opened\"").unwrap();
        assert_eq!(c, Condition::PortOpened);
        assert_eq!(
            serde_json::from_str::<Condition>("\"address_moved\"").unwrap(),
            Condition::AddressMoved
        );
    }
}
