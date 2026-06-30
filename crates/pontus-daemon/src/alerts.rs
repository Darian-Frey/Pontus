//! Alert delivery (F-019).
//!
//! Rule *matching* is headless (`pontus_core::alert`); this module is the daemon's
//! delivery side — turning a fired [`Alert`] into a notification on each of its
//! channels. Channels: `log` (always available), `desktop` (`notify-send`),
//! `webhook` (generic JSON POST), `slack`/`discord` (their incoming-webhook JSON
//! shapes), and `email` (SMTP via lettre, rustls).

use crate::config::{Channels, EmailChannel, WebhookChannel};
use crate::logging;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use pontus_core::alert::Alert;
use std::time::Duration;

/// Timeout for SMTP delivery so a hung mail server can't stall the daemon.
const SMTP_TIMEOUT: Duration = Duration::from_secs(15);

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
            "email" => email(alert, channels.email.as_ref()),
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

fn email(alert: &Alert, cfg: Option<&EmailChannel>) {
    let Some(cfg) = cfg else {
        logging::warn(&format!("alert {:?}: email not configured, skipping", alert.rule));
        return;
    };
    match send_email(alert, cfg) {
        Ok(()) => logging::info(&format!("alert {:?}: delivered via email", alert.rule)),
        Err(e) => logging::warn(&format!("alert {:?}: email delivery failed: {e}", alert.rule)),
    }
}

/// Build and send one alert as an email. Returns a human error string on failure
/// (logged by the caller, never fatal).
fn send_email(alert: &Alert, cfg: &EmailChannel) -> Result<(), String> {
    let from = cfg.from.parse().map_err(|e| format!("bad `from` address {:?}: {e}", cfg.from))?;
    let body = format!(
        "{summary}\n\nHost:   {ip} ({identity})\nRule:   {rule}\nPlugin/source: alert\n",
        summary = alert.summary,
        ip = alert.ip,
        identity = alert.identity,
        rule = alert.rule,
    );
    let mut builder = Message::builder()
        .from(from)
        .subject(format!("Pontus alert: {}", alert.rule));
    for to in &cfg.to {
        builder = builder.to(to.parse().map_err(|e| format!("bad `to` address {to:?}: {e}"))?);
    }
    let message = builder.body(body).map_err(|e| format!("building message: {e}"))?;

    // Transport per TLS mode: starttls (587), implicit tls (465), or plaintext.
    let transport = match cfg.tls.as_str() {
        "tls" => SmtpTransport::relay(&cfg.smtp_server).map_err(|e| e.to_string())?,
        "starttls" => SmtpTransport::starttls_relay(&cfg.smtp_server).map_err(|e| e.to_string())?,
        _ => SmtpTransport::builder_dangerous(&cfg.smtp_server),
    };
    let mut transport = transport.port(cfg.smtp_port).timeout(Some(SMTP_TIMEOUT));
    if let (Some(user), Some(pass)) = (&cfg.username, &cfg.password) {
        transport = transport.credentials(Credentials::new(user.clone(), pass.clone()));
    }
    transport.build().send(&message).map_err(|e| e.to_string())?;
    Ok(())
}
