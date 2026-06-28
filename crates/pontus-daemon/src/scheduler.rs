//! Scan scheduling (F-018).
//!
//! Each job runs on its own cadence. A run shells out to `pontus-cli scan` with
//! arguments derived from the job, inheriting the child's stdout/stderr so scan
//! progress flows through the daemon's output. Scans are serialised by a shared
//! lock so only one writes to the SQLite store at a time.

use crate::config::{Config, Job};
use crate::logging;
use std::sync::Arc;
use std::time::Instant;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::sleep;

/// Build the `pontus-cli` argument vector for one job (the `scan` subcommand
/// onwards). Pure and deterministic so it can be unit-tested without spawning.
pub fn build_scan_args(db: &str, job: &Job) -> Vec<String> {
    let mut args = vec!["scan".to_string(), job.targets.clone()];
    args.push("--db".to_string());
    args.push(db.to_string());
    for scope in job.effective_scope() {
        args.push("--scope".to_string());
        args.push(scope);
    }
    if let Some(op) = &job.operator {
        args.push("--operator".to_string());
        args.push(op.clone());
    }
    if let Some(ports) = &job.ports {
        args.push("--ports".to_string());
        args.push(ports.clone());
    }
    if let Some(n) = job.top_ports {
        args.push("--top-ports".to_string());
        args.push(n.to_string());
    }
    if let Some(udp) = &job.udp_ports {
        args.push("--udp-ports".to_string());
        args.push(udp.clone());
    }
    if let Some(det) = &job.detector {
        args.push("--detector".to_string());
        args.push(det.clone());
    }
    if job.assess_vulns {
        args.push("--assess-vulns".to_string());
    }
    if job.inspect {
        args.push("--inspect".to_string());
    }
    if job.no_rdns {
        args.push("--no-rdns".to_string());
    }
    if job.no_traceroute {
        args.push("--no-traceroute".to_string());
    }
    args
}

/// Run one job's scan once, holding the scan lock for the duration so concurrent
/// jobs never write to the store at the same time.
async fn run_once(cfg: &Config, job: &Job, lock: &Mutex<()>) {
    let _guard = lock.lock().await;
    let args = build_scan_args(&cfg.db, job);
    logging::info(&format!("job {:?}: scanning {} ...", job.name, job.targets));
    let started = Instant::now();
    let result = Command::new(&cfg.cli).args(&args).status().await;
    let secs = started.elapsed().as_secs_f64();
    match result {
        Ok(status) if status.success() => {
            logging::info(&format!("job {:?}: completed in {secs:.1}s", job.name));
        }
        Ok(status) => {
            logging::warn(&format!("job {:?}: {status} after {secs:.1}s", job.name));
        }
        Err(e) => {
            logging::error(&format!(
                "job {:?}: could not launch {:?} ({e}) — is the CLI on PATH / `cli` set correctly?",
                job.name, cfg.cli
            ));
        }
    }
}

/// Drive a single job forever: an optional immediate run, then on the interval.
/// When `once` is set, run exactly once and return (used by `--once`).
pub async fn run_job(cfg: Arc<Config>, job: Job, lock: Arc<Mutex<()>>, once: bool) {
    if once {
        run_once(&cfg, &job, &lock).await;
        return;
    }
    let interval = job.interval();
    if cfg.run_at_start {
        run_once(&cfg, &job, &lock).await;
    }
    loop {
        sleep(interval).await;
        run_once(&cfg, &job, &lock).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Job;

    fn job() -> Job {
        Job {
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
        }
    }

    #[test]
    fn minimal_job_builds_scan_with_defaulted_scope() {
        let args = build_scan_args("lan.db", &job());
        assert_eq!(
            args,
            vec!["scan", "192.168.1.0/24", "--db", "lan.db", "--scope", "192.168.1.0/24"]
        );
    }

    #[test]
    fn full_job_maps_every_field_to_a_flag() {
        let mut j = job();
        j.scope = vec!["10.0.0.0/24".into(), "10.0.1.0/24".into()];
        j.operator = Some("daemon".into());
        j.ports = Some("22,80".into());
        j.top_ports = Some(100);
        j.udp_ports = Some("53,161".into());
        j.detector = Some("nmap".into());
        j.assess_vulns = true;
        j.inspect = true;
        j.no_rdns = true;
        j.no_traceroute = true;

        let args = build_scan_args("p.db", &j);

        // Both scopes are passed through as repeated flags.
        assert_eq!(args.iter().filter(|a| *a == "--scope").count(), 2);
        assert!(args.windows(2).any(|w| w == ["--scope", "10.0.1.0/24"]));
        assert!(args.windows(2).any(|w| w == ["--top-ports", "100"]));
        assert!(args.windows(2).any(|w| w == ["--detector", "nmap"]));
        assert!(args.windows(2).any(|w| w == ["--udp-ports", "53,161"]));
        // Boolean flags appear without a value.
        for flag in ["--assess-vulns", "--inspect", "--no-rdns", "--no-traceroute"] {
            assert!(args.iter().any(|a| a == flag), "missing {flag}");
        }
    }

    #[test]
    fn explicit_scope_overrides_the_target_default() {
        let mut j = job();
        j.scope = vec!["10.0.0.0/8".into()];
        let args = build_scan_args("p.db", &j);
        assert!(args.windows(2).any(|w| w == ["--scope", "10.0.0.0/8"]));
        assert!(!args.windows(2).any(|w| w == ["--scope", "192.168.1.0/24"]));
    }
}
