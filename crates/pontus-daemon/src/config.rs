//! Daemon configuration (F-018).
//!
//! A TOML file describes the store to write to, the path to the privileged CLI,
//! and a list of scheduled scan jobs. The daemon runs each job on its interval,
//! shelling out to `pontus-cli scan` (D-008) so all scan orchestration — and the
//! raw-socket capability — stays on the one binary.

use pontus_core::alert::{self, Condition};
use serde::Deserialize;
use std::time::Duration;

/// Known alert channels. `webhook`/`slack`/`discord` require a matching
/// `[channels.*]` table with a URL; `log` and `desktop` need no configuration.
const KNOWN_CHANNELS: [&str; 5] = ["log", "desktop", "webhook", "slack", "discord"];

/// Top-level daemon configuration, deserialised from the TOML config file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Store path passed to every scan (`pontus-cli scan --db`).
    #[serde(default = "default_db")]
    pub db: String,
    /// Path to the (capability-granted) CLI binary to invoke.
    #[serde(default = "default_cli")]
    pub cli: String,
    /// Run every job once on startup before entering its interval cadence.
    /// Defaults to true — a fresh daemon produces a baseline immediately.
    #[serde(default = "default_true")]
    pub run_at_start: bool,
    /// Scheduled scan jobs. Each `[[job]]` table is one entry.
    #[serde(rename = "job", default)]
    pub jobs: Vec<Job>,
    /// Alert rules evaluated against drift after each scheduled scan (F-019).
    #[serde(rename = "alert", default)]
    pub alerts: Vec<AlertRule>,
    /// Delivery channel configuration (URLs for webhook/Slack/Discord).
    #[serde(default)]
    pub channels: Channels,
}

/// An alert rule as written in the config. `on` deserialises straight to the
/// core [`Condition`] (snake_case strings like `port_opened`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlertRule {
    /// Human label, used in logs and the delivered payload.
    pub name: String,
    /// The change to fire on (`port_opened`, `port_closed`, `host_new`,
    /// `host_vanished`, `host_changed`, `address_moved`).
    pub on: Condition,
    /// Restrict port conditions to this port (omit = any).
    #[serde(default)]
    pub port: Option<u16>,
    /// Restrict port conditions to this protocol (omit = any).
    #[serde(default)]
    pub proto: Option<String>,
    /// Channels to deliver matches to (names from [`KNOWN_CHANNELS`]).
    pub channels: Vec<String>,
}

/// Delivery channel configuration. Each is optional; a rule referencing a channel
/// whose config is absent is rejected at load.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Channels {
    #[serde(default)]
    pub webhook: Option<WebhookChannel>,
    #[serde(default)]
    pub slack: Option<WebhookChannel>,
    #[serde(default)]
    pub discord: Option<WebhookChannel>,
}

/// A webhook-style channel: an HTTPS endpoint to POST JSON to.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookChannel {
    pub url: String,
}

/// One scheduled scan. Fields mirror the `pontus-cli scan` flags they map to, so
/// a job is "a saved scan plus a cadence".
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    /// Human label, used in logs. Must be unique across jobs.
    pub name: String,
    /// Target range or host (`pontus-cli scan <targets>`).
    pub targets: String,
    /// How often to rescan, e.g. `90s`, `15m`, `6h`, `1d`.
    pub interval: String,
    /// Authorised scope(s) (`--scope`). Defaults to the target range when omitted;
    /// scope is still enforced unconditionally by the CLI/core (F-007).
    #[serde(default)]
    pub scope: Vec<String>,
    /// Operator name recorded in the audit log (`--operator`).
    #[serde(default)]
    pub operator: Option<String>,
    /// TCP ports (`--ports`). Omitted → the CLI default set.
    #[serde(default)]
    pub ports: Option<String>,
    /// Union the N most common TCP ports (`--top-ports`).
    #[serde(default)]
    pub top_ports: Option<u16>,
    /// UDP ports (`--udp-ports`).
    #[serde(default)]
    pub udp_ports: Option<String>,
    /// Match services to CVEs and enrich with EPSS/KEV (`--assess-vulns`).
    #[serde(default)]
    pub assess_vulns: bool,
    /// Deep-inspect TLS/HTTP (`--inspect`).
    #[serde(default)]
    pub inspect: bool,
    /// Service detector: `native` (default) or `nmap` (`--detector`).
    #[serde(default)]
    pub detector: Option<String>,
    /// Skip reverse-DNS (`--no-rdns`).
    #[serde(default)]
    pub no_rdns: bool,
    /// Skip the traceroute/topology pass (`--no-traceroute`).
    #[serde(default)]
    pub no_traceroute: bool,
}

fn default_db() -> String {
    "pontus.db".to_string()
}
fn default_cli() -> String {
    "pontus-cli".to_string()
}
fn default_true() -> bool {
    true
}

/// Errors loading or validating a config.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading config {0}: {1}")]
    Read(String, std::io::Error),
    #[error("parsing config: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Invalid(String),
}

impl Config {
    /// Load and validate a config from a TOML file.
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Read(path.to_string(), e))?;
        let cfg: Config = toml::from_str(&text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Reject configs that would fail at run time: no jobs, blank/duplicate names,
    /// empty targets, or an unparseable interval.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.jobs.is_empty() {
            return Err(ConfigError::Invalid("no [[job]] entries defined".into()));
        }
        let mut seen = std::collections::HashSet::new();
        for job in &self.jobs {
            if job.name.trim().is_empty() {
                return Err(ConfigError::Invalid("a job has an empty name".into()));
            }
            if !seen.insert(job.name.as_str()) {
                return Err(ConfigError::Invalid(format!("duplicate job name {:?}", job.name)));
            }
            if job.targets.trim().is_empty() {
                return Err(ConfigError::Invalid(format!("job {:?} has empty targets", job.name)));
            }
            parse_duration(&job.interval)
                .map_err(|e| ConfigError::Invalid(format!("job {:?}: {e}", job.name)))?;
        }

        let mut alert_names = std::collections::HashSet::new();
        for a in &self.alerts {
            if a.name.trim().is_empty() {
                return Err(ConfigError::Invalid("an alert has an empty name".into()));
            }
            if !alert_names.insert(a.name.as_str()) {
                return Err(ConfigError::Invalid(format!("duplicate alert name {:?}", a.name)));
            }
            if a.channels.is_empty() {
                return Err(ConfigError::Invalid(format!("alert {:?} lists no channels", a.name)));
            }
            for ch in &a.channels {
                if !KNOWN_CHANNELS.contains(&ch.as_str()) {
                    return Err(ConfigError::Invalid(format!(
                        "alert {:?}: unknown channel {ch:?} (known: {})",
                        a.name,
                        KNOWN_CHANNELS.join(", ")
                    )));
                }
                let configured = match ch.as_str() {
                    "webhook" => self.channels.webhook.is_some(),
                    "slack" => self.channels.slack.is_some(),
                    "discord" => self.channels.discord.is_some(),
                    _ => true, // log/desktop need no config
                };
                if !configured {
                    return Err(ConfigError::Invalid(format!(
                        "alert {:?}: channel {ch:?} has no [channels.{ch}] url",
                        a.name
                    )));
                }
            }
        }
        Ok(())
    }

    /// The configured alert rules as core [`alert::Rule`]s.
    pub fn rules(&self) -> Vec<alert::Rule> {
        self.alerts
            .iter()
            .map(|a| alert::Rule {
                name: a.name.clone(),
                condition: a.on,
                port: a.port,
                proto: a.proto.clone(),
                channels: a.channels.clone(),
            })
            .collect()
    }
}

impl Job {
    /// The scope to enforce: explicit scopes if given, else the target range.
    pub fn effective_scope(&self) -> Vec<String> {
        if self.scope.is_empty() {
            vec![self.targets.clone()]
        } else {
            self.scope.clone()
        }
    }

    /// The parsed rescan interval. Safe to unwrap after `validate()`.
    pub fn interval(&self) -> Duration {
        parse_duration(&self.interval).expect("interval validated at load")
    }
}

/// Parse a human duration like `30s`, `15m`, `6h`, `2d` into a [`Duration`].
/// A bare number is interpreted as seconds. Zero and overflow are rejected so a
/// job can never spin in a tight loop.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty interval".into());
    }
    let (num, unit_secs) = match s.chars().last().unwrap() {
        'a'..='z' | 'A'..='Z' => {
            let (n, u) = s.split_at(s.len() - 1);
            let mult = match u {
                "s" | "S" => 1u64,
                "m" | "M" => 60,
                "h" | "H" => 3600,
                "d" | "D" => 86_400,
                other => return Err(format!("unknown interval unit {other:?} (use s/m/h/d)")),
            };
            (n.trim(), mult)
        }
        _ => (s, 1),
    };
    let value: u64 = num
        .parse()
        .map_err(|_| format!("not a number: {num:?}"))?;
    let secs = value
        .checked_mul(unit_secs)
        .ok_or_else(|| "interval too large".to_string())?;
    if secs == 0 {
        return Err("interval must be greater than zero".into());
    }
    Ok(Duration::from_secs(secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_unit() {
        assert_eq!(parse_duration("45s").unwrap(), Duration::from_secs(45));
        assert_eq!(parse_duration("15m").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_duration("6h").unwrap(), Duration::from_secs(21_600));
        assert_eq!(parse_duration("2d").unwrap(), Duration::from_secs(172_800));
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90), "bare number is seconds");
    }

    #[test]
    fn rejects_zero_unknown_and_garbage() {
        assert!(parse_duration("0s").is_err(), "zero would spin");
        assert!(parse_duration("10y").is_err(), "unknown unit");
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("").is_err());
    }

    #[test]
    fn scope_defaults_to_targets() {
        let job = Job {
            name: "j".into(),
            targets: "192.168.1.0/24".into(),
            interval: "1h".into(),
            scope: vec![],
            operator: None,
            ports: None,
            top_ports: None,
            udp_ports: None,
            assess_vulns: false,
            inspect: false,
            detector: None,
            no_rdns: false,
            no_traceroute: false,
        };
        assert_eq!(job.effective_scope(), vec!["192.168.1.0/24".to_string()]);
    }

    #[test]
    fn validate_rejects_empty_and_duplicate() {
        let base = || Job {
            name: "a".into(),
            targets: "10.0.0.0/24".into(),
            interval: "1h".into(),
            scope: vec![],
            operator: None,
            ports: None,
            top_ports: None,
            udp_ports: None,
            assess_vulns: false,
            inspect: false,
            detector: None,
            no_rdns: false,
            no_traceroute: false,
        };

        let cfg = |jobs| Config {
            db: "x".into(),
            cli: "c".into(),
            run_at_start: true,
            jobs,
            alerts: vec![],
            channels: Channels::default(),
        };

        assert!(cfg(vec![]).validate().is_err(), "no jobs");
        assert!(cfg(vec![base(), base()]).validate().is_err(), "duplicate name");
        assert!(cfg(vec![base()]).validate().is_ok());
    }

    #[test]
    fn alert_referencing_unconfigured_channel_is_rejected() {
        let text = r#"
[[job]]
name = "j"
targets = "10.0.0.0/24"
interval = "1h"

[[alert]]
name = "ssh"
on = "port_opened"
port = 22
channels = ["slack"]
"#;
        // slack channel referenced but no [channels.slack] url configured.
        let cfg: Config = toml::from_str(text).unwrap();
        assert!(cfg.validate().is_err(), "slack channel has no url");
    }

    #[test]
    fn alert_rules_parse_and_convert_to_core_rules() {
        let text = r#"
[[job]]
name = "j"
targets = "10.0.0.0/24"
interval = "1h"

[channels.slack]
url = "https://hooks.slack.com/services/XXX"

[[alert]]
name = "ssh-opened"
on = "port_opened"
port = 22
proto = "tcp"
channels = ["log", "slack"]

[[alert]]
name = "new-host"
on = "host_new"
channels = ["log"]
"#;
        let cfg: Config = toml::from_str(text).unwrap();
        cfg.validate().unwrap();
        let rules = cfg.rules();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].condition, Condition::PortOpened);
        assert_eq!(rules[0].port, Some(22));
        assert_eq!(rules[0].channels, vec!["log", "slack"]);
        assert_eq!(rules[1].condition, Condition::HostNew);
    }

    #[test]
    fn full_toml_round_trips() {
        let text = r#"
db = "lan.db"
cli = "/usr/local/bin/pontus-cli"
run_at_start = false

[[job]]
name = "servers-hourly"
targets = "192.168.1.0/24"
interval = "1h"
scope = ["192.168.1.0/24"]
ports = "22,80,443"
top_ports = 100
assess_vulns = true
operator = "daemon"

[[job]]
name = "iot-daily"
targets = "192.168.2.0/24"
interval = "1d"
udp_ports = "53,161,5353"
"#;
        let cfg: Config = toml::from_str(text).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.db, "lan.db");
        assert!(!cfg.run_at_start);
        assert_eq!(cfg.jobs.len(), 2);
        assert_eq!(cfg.jobs[0].interval(), Duration::from_secs(3600));
        assert!(cfg.jobs[0].assess_vulns);
        assert_eq!(cfg.jobs[1].udp_ports.as_deref(), Some("53,161,5353"));
    }
}
