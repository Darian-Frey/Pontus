//! Scan scheduling (F-018).
//!
//! Each job runs on its own cadence. A run shells out to `pontus-cli scan` with
//! arguments derived from the job, inheriting the child's stdout/stderr so scan
//! progress flows through the daemon's output. Scans are serialised by a shared
//! lock so only one writes to the SQLite store at a time.

use crate::alerts;
use crate::config::{Config, Job};
use crate::logging;
use pontus_core::alert::{self, Alert};
use pontus_core::{Store, diff_observations};
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
/// jobs never write to the store at the same time. On success, evaluate alert
/// rules against the drift since the previous run of this job and deliver matches.
async fn run_once(cfg: &Arc<Config>, rules: &Arc<Vec<alert::Rule>>, job: &Job, lock: &Mutex<()>) {
    let _guard = lock.lock().await;
    let args = build_scan_args(&cfg.db, job);
    logging::info(&format!("job {:?}: scanning {} ...", job.name, job.targets));
    let started = Instant::now();
    let result = Command::new(&cfg.cli).args(&args).status().await;
    let secs = started.elapsed().as_secs_f64();
    match result {
        Ok(status) if status.success() => {
            logging::info(&format!("job {:?}: completed in {secs:.1}s", job.name));
            if !rules.is_empty() {
                process_alerts(cfg, rules, job).await;
            }
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

/// Read the store, diff this job's latest scan against its previous one, evaluate
/// the rules and deliver any alerts. The store read + HTTP delivery are blocking,
/// so they run on a blocking thread rather than stalling the async runtime.
async fn process_alerts(cfg: &Arc<Config>, rules: &Arc<Vec<alert::Rule>>, job: &Job) {
    let cfg = Arc::clone(cfg);
    let rules = Arc::clone(rules);
    let name = job.name.clone();
    let targets = job.targets.clone();
    let joined = tokio::task::spawn_blocking(move || {
        match evaluate_drift(&cfg.db, &targets, &rules) {
            Ok(alerts) => {
                for a in &alerts {
                    alerts::deliver(&cfg.channels, a);
                }
                if !alerts.is_empty() {
                    logging::info(&format!("job {name:?}: {} alert(s) fired", alerts.len()));
                }
            }
            Err(e) => logging::warn(&format!("job {name:?}: alert evaluation skipped — {e}")),
        }
    })
    .await;
    if let Err(e) = joined {
        logging::warn(&format!("job {:?}: alert task panicked: {e}", job.name));
    }
}

/// Diff this job's two most recent finished scans (matched by target range) and
/// evaluate the rules. Returns no alerts on the first run (no prior scan to
/// compare against), which is what makes alerts change-triggered rather than a
/// flood of "new host" on day one.
fn evaluate_drift(db: &str, targets: &str, rules: &[alert::Rule]) -> Result<Vec<Alert>, String> {
    let store = Store::open(db).map_err(|e| e.to_string())?;
    let scans = store.recent_scans(64).map_err(|e| e.to_string())?;
    // recent_scans is newest-first; keep this job's finished scans in that order.
    let mine: Vec<i64> = scans
        .iter()
        .filter(|s| s.targets == targets && s.finished_at.is_some())
        .map(|s| s.id)
        .collect();
    if mine.len() < 2 {
        return Ok(Vec::new());
    }
    let latest = store.observations_for_scan(mine[0]).map_err(|e| e.to_string())?;
    let previous = store.observations_for_scan(mine[1]).map_err(|e| e.to_string())?;
    let diffs = diff_observations(&previous, &latest);
    Ok(alert::evaluate(rules, &diffs))
}

/// Drive a single job forever: an optional immediate run, then on the interval.
/// When `once` is set, run exactly once and return (used by `--once`).
pub async fn run_job(
    cfg: Arc<Config>,
    rules: Arc<Vec<alert::Rule>>,
    job: Job,
    lock: Arc<Mutex<()>>,
    once: bool,
) {
    if once {
        run_once(&cfg, &rules, &job, &lock).await;
        return;
    }
    let interval = job.interval();
    if cfg.run_at_start {
        run_once(&cfg, &rules, &job, &lock).await;
    }
    loop {
        sleep(interval).await;
        run_once(&cfg, &rules, &job, &lock).await;
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

    // --- evaluate_drift: store → diff → rule evaluation glue (F-019) ---

    use pontus_core::alert::Condition;
    use pontus_core::{IdentitySignals, ObservationState, PortObservation, Store};
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    fn temp_db() -> String {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!("pontus-daemon-drift-{}-{n}.db", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }

    fn state(ports: &[u16]) -> ObservationState {
        ObservationState {
            up: true,
            open_ports: ports
                .iter()
                .map(|&port| PortObservation { port, proto: "tcp".into(), ..Default::default() })
                .collect(),
            ..Default::default()
        }
    }

    fn record_scan(store: &Store, targets: &str, mac: &str, ports: &[u16]) {
        let s = store.begin_scan(targets, targets, Some("test")).unwrap();
        let sig = IdentitySignals {
            mac: Some(mac.to_string()),
            ip: Some("192.168.1.10".parse().unwrap()),
            ..Default::default()
        };
        store.record(&sig, s, &state(ports)).unwrap();
        store.finish_scan(s).unwrap();
    }

    fn rule(condition: Condition, port: Option<u16>) -> alert::Rule {
        alert::Rule { name: "r".into(), condition, port, proto: None, channels: vec!["log".into()] }
    }

    #[test]
    fn first_run_with_no_prior_scan_fires_nothing() {
        let db = temp_db();
        let store = Store::open(&db).unwrap();
        record_scan(&store, "192.168.1.0/24", "aa:bb:cc:dd:ee:ff", &[22]);

        let alerts = evaluate_drift(&db, "192.168.1.0/24", &[rule(Condition::PortOpened, None)]).unwrap();
        assert!(alerts.is_empty(), "no baseline yet → no alerts");
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn a_newly_opened_port_fires_exactly_one_alert() {
        let db = temp_db();
        let store = Store::open(&db).unwrap();
        let mac = "aa:bb:cc:dd:ee:ff";
        record_scan(&store, "192.168.1.0/24", mac, &[22]); // baseline: only 22
        record_scan(&store, "192.168.1.0/24", mac, &[22, 80]); // 80 opens

        let alerts =
            evaluate_drift(&db, "192.168.1.0/24", &[rule(Condition::PortOpened, Some(80))]).unwrap();
        assert_eq!(alerts.len(), 1, "exactly one alert for the newly opened port (F-019)");
        assert!(alerts[0].summary.contains("port tcp/80 opened"));

        // The condition persists but a third identical scan reports no new change.
        record_scan(&store, "192.168.1.0/24", mac, &[22, 80]);
        let again =
            evaluate_drift(&db, "192.168.1.0/24", &[rule(Condition::PortOpened, Some(80))]).unwrap();
        assert!(again.is_empty(), "an unchanged port does not re-alert");
        let _ = std::fs::remove_file(&db);
    }

    #[test]
    fn drift_is_scoped_to_the_jobs_own_targets() {
        // A different job's scans interleaved in the same store must not pollute
        // this job's diff (evaluate_drift matches on the target range).
        let db = temp_db();
        let store = Store::open(&db).unwrap();
        record_scan(&store, "192.168.1.0/24", "aa:bb:cc:dd:ee:ff", &[22]);
        record_scan(&store, "10.0.0.0/24", "11:22:33:44:55:66", &[443]); // other job, between
        record_scan(&store, "192.168.1.0/24", "aa:bb:cc:dd:ee:ff", &[22, 80]);

        let alerts =
            evaluate_drift(&db, "192.168.1.0/24", &[rule(Condition::PortOpened, None)]).unwrap();
        assert_eq!(alerts.len(), 1, "diffed against this job's own previous scan, not the interleaved one");
        assert!(alerts[0].summary.contains("tcp/80"));
        let _ = std::fs::remove_file(&db);
    }
}
