//! `pontus-daemon` — unattended scheduled rescans (F-018).
//!
//! Reads a TOML config of scan jobs and runs each on its interval by shelling out
//! to the capability-granted `pontus-cli` (D-008), so results land in the store as
//! ordinary append-only observations against the resolved assets (D-007). The
//! daemon itself holds no raw-socket privilege and never touches the store
//! directly — it is purely a scheduler.

mod alerts;
mod config;
mod logging;
mod scheduler;

use clap::Parser;
use config::Config;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Parser)]
#[command(name = "pontus-daemon", about = "Scheduled, unattended rescans for Pontus (F-018)")]
struct Cli {
    /// Path to the TOML config of scan jobs.
    #[arg(long, default_value = "pontus-daemon.toml")]
    config: String,
    /// Run every job exactly once and exit (ignores intervals). Useful for a
    /// dry run, a cron-driven invocation, or verifying a config.
    #[arg(long)]
    once: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let cfg = match Config::load(&cli.config) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            logging::error(&format!("{e}"));
            return ExitCode::FAILURE;
        }
    };

    logging::info(&format!(
        "pontus-daemon starting: {} job(s), store {:?}, cli {:?}{}",
        cfg.jobs.len(),
        cfg.db,
        cfg.cli,
        if cli.once { " (run-once)" } else { "" }
    ));
    for job in &cfg.jobs {
        logging::info(&format!(
            "  job {:?}: {} every {}",
            job.name, job.targets, job.interval
        ));
    }
    let rules = Arc::new(cfg.rules());
    if !rules.is_empty() {
        logging::info(&format!("  {} alert rule(s) active", rules.len()));
    }

    // One SQLite writer at a time: scans serialise through this lock.
    let scan_lock = Arc::new(Mutex::new(()));

    let mut handles = Vec::new();
    for job in cfg.jobs.clone() {
        let cfg = Arc::clone(&cfg);
        let rules = Arc::clone(&rules);
        let lock = Arc::clone(&scan_lock);
        let once = cli.once;
        handles.push(tokio::spawn(async move {
            scheduler::run_job(cfg, rules, job, lock, once).await;
        }));
    }

    if cli.once {
        // Each task runs its single scan and returns; wait for all then exit.
        for h in handles {
            let _ = h.await;
        }
        logging::info("all jobs ran once; exiting");
        return ExitCode::SUCCESS;
    }

    // Run until interrupted. The job tasks loop forever; Ctrl-C (or SIGTERM under a
    // service manager) ends the daemon, abandoning any in-flight scan child.
    match tokio::signal::ctrl_c().await {
        Ok(()) => logging::info("shutdown signal received; stopping"),
        Err(e) => logging::error(&format!("failed to listen for shutdown signal: {e}")),
    }
    for h in handles {
        h.abort();
    }
    ExitCode::SUCCESS
}
