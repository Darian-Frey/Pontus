//! Minimal timestamped logging to stderr.
//!
//! Deliberately tiny — no `tracing`/`log` dependency. One line per event, ISO 8601
//! timestamp first, so output is greppable and plays nicely with journald/syslog
//! when the daemon runs under a service manager.

use chrono::Utc;

pub fn info(msg: &str) {
    line("INFO", msg);
}

pub fn warn(msg: &str) {
    line("WARN", msg);
}

pub fn error(msg: &str) {
    line("ERROR", msg);
}

fn line(level: &str, msg: &str) {
    eprintln!("{} [{level}] {msg}", Utc::now().to_rfc3339());
}
