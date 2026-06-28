//! Alert delivery (F-019).
//!
//! Rule *matching* is headless (`pontus_core::alert`); this module is the daemon's
//! delivery side — turning a fired [`Alert`] into a notification on each of its
//! channels. Channels: `log` (always available), `desktop` (`notify-send`),
//! `webhook` (generic JSON POST), `slack`/`discord` (their incoming-webhook JSON
//! shapes). Email is intentionally not yet implemented (an SMTP dependency is a
//! separate decision) — see F-019's remaining slice.

use crate::config::{Channels, WebhookChannel};
use crate::logging;
use pontus_core::alert::Alert;
use std::time::Duration;

/// HTTP timeout for webhook delivery so a hung endpoint can't stall the daemon.
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);

/// Deliver one alert to each of its channels. Failures are logged, never fatal —
/// a broken webhook must not take down monitoring.
pub fn deliver(channels: &Channels, alert: &Alert) {
    for ch in &alert.channels {
        match ch.as_str() {
            "log" => logging::warn(&format!("ALERT [{}] {}", alert.rule, alert.summary)),
            "desktop" => desktop(alert),
            "webhook" => post(alert, "webhook", channels.webhook.as_ref(), generic_body(alert)),
            "slack" => post(alert, "slack", channels.slack.as_ref(), text_body("text", alert)),
            "discord" => post(alert, "discord", channels.discord.as_ref(), text_body("content", alert)),
            other => logging::warn(&format!("alert {:?}: unknown channel {other:?}", alert.rule)),
        }
    }
}

/// The full alert as JSON, for a generic webhook receiver.
fn generic_body(alert: &Alert) -> String {
    serde_json::to_string(alert).unwrap_or_else(|_| "{}".to_string())
}

/// `{ "<field>": "[rule] summary" }` — the Slack (`text`) / Discord (`content`) shape.
fn text_body(field: &str, alert: &Alert) -> String {
    let msg = serde_json::json!({ field: format!("[{}] {}", alert.rule, alert.summary) });
    msg.to_string()
}

fn post(alert: &Alert, channel: &str, cfg: Option<&WebhookChannel>, body: String) {
    let Some(cfg) = cfg else {
        // validate() guarantees configuration exists; this is defence in depth.
        logging::warn(&format!("alert {:?}: {channel} not configured, skipping", alert.rule));
        return;
    };
    let agent = ureq::AgentBuilder::new()
        .timeout(WEBHOOK_TIMEOUT)
        .build();
    match agent
        .post(&cfg.url)
        .set("Content-Type", "application/json")
        .send_string(&body)
    {
        Ok(_) => logging::info(&format!("alert {:?}: delivered via {channel}", alert.rule)),
        Err(e) => logging::warn(&format!("alert {:?}: {channel} delivery failed: {e}", alert.rule)),
    }
}

fn desktop(alert: &Alert) {
    let title = format!("Pontus: {}", alert.rule);
    match std::process::Command::new("notify-send")
        .arg(&title)
        .arg(&alert.summary)
        .status()
    {
        Ok(s) if s.success() => {}
        Ok(s) => logging::warn(&format!("alert {:?}: notify-send exited {s}", alert.rule)),
        Err(e) => logging::warn(&format!(
            "alert {:?}: desktop notification failed ({e}) — is notify-send installed?",
            alert.rule
        )),
    }
}
