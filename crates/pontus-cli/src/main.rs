//! `pontus-cli` — the Phase 1 driver and reference consumer of `pontus-core`
//! (F-005). Everything it does goes through the headless core: scope enforcement,
//! identity resolution and the append-only store all live there, not here.

use clap::{Parser, Subcommand};
use ipnet::IpNet;
use pontus_core::{IdentitySignals, ObservationState, PortObservation, Scope, Store};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "pontus-cli",
    version,
    about = "Pontus — GUI-native network scanner & asset inventory (CLI front-end)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a target range and record assets + observations.
    Scan(ScanArgs),
    /// List the assets currently in the store.
    Assets {
        #[arg(long, default_value = "pontus.db")]
        db: String,
    },
}

#[derive(Parser)]
struct ScanArgs {
    /// Target range, e.g. 192.168.1.0/24 or a single host.
    targets: String,
    /// Authorised scope (repeatable). Mandatory — nothing is scanned outside it (F-007).
    #[arg(long = "scope", required = true, value_name = "CIDR|IP")]
    scope: Vec<String>,
    /// Store path.
    #[arg(long, default_value = "pontus.db")]
    db: String,
    /// Operator name, recorded in the audit log.
    #[arg(long)]
    operator: Option<String>,
    /// Comma-separated TCP ports used for the interim connect-based discovery.
    #[arg(long, default_value = "22,80,443,445,3389,8080")]
    ports: String,
    /// Per-port connect timeout, milliseconds.
    #[arg(long, default_value_t = 400)]
    timeout_ms: u64,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Scan(args) => run_scan(args),
        Command::Assets { db } => list_assets(&db),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_scan(args: ScanArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Scope is built and validated before anything else happens.
    let scope = Scope::parse(&args.scope)?;
    let targets: IpNet = pontus_core::scope::parse_cidr_or_host(&args.targets)?;
    let ports = parse_ports(&args.ports)?;
    let timeout = Duration::from_millis(args.timeout_ms);

    let store = Store::open(&args.db)?;
    let scan_id = store.begin_scan(&args.targets, &scope.to_string(), args.operator.as_deref())?;

    println!("scope: {scope}");
    println!("scan {scan_id}: probing {} ...", args.targets);

    let mut up = 0u64;
    let mut refused = 0u64;
    for host in targets.hosts() {
        // Unconditional gate: never send a packet to a host outside scope (F-007).
        if scope.ensure(host).is_err() {
            refused += 1;
            continue;
        }
        if let Some(state) = probe(host, &ports, timeout) {
            // Interim discovery yields only an IP; MAC/host-key signals arrive
            // with the raw-socket engine (F-001) in the next increment.
            store.record(&IdentitySignals::from_ip(host), scan_id, &state)?;
            up += 1;
        }
    }

    store.finish_scan(scan_id)?;
    println!(
        "done: {up} host(s) up, {refused} target(s) refused as out-of-scope; \
         {} asset(s), {} observation(s) total",
        store.asset_count()?,
        store.observation_count()?
    );
    Ok(())
}

fn list_assets(db: &str) -> Result<(), Box<dyn std::error::Error>> {
    let store = Store::open(db)?;
    let assets = store.list_assets()?;
    if assets.is_empty() {
        println!("no assets recorded yet");
        return Ok(());
    }
    println!(
        "{:>4}  {:<9}  {:<24}  {:<16}  {:>4}  LAST SEEN",
        "ID", "ANCHOR", "IDENTITY", "LAST IP", "OBS"
    );
    for a in assets {
        println!(
            "{:>4}  {:<9}  {:<24}  {:<16}  {:>4}  {}",
            a.id,
            a.identity_kind,
            a.identity_value,
            a.last_ip.as_deref().unwrap_or("-"),
            a.observations,
            a.last_seen,
        );
    }
    Ok(())
}

/// Interim host discovery: a TCP connect "ping". A successful connect *or* a
/// connection-refused both prove the host is reachable; a timeout is treated as
/// down. This works without `CAP_NET_RAW`; it is a stand-in for the raw-socket
/// ARP/ICMP/SYN engine (F-001), not the final design.
fn probe(host: IpAddr, ports: &[u16], timeout: Duration) -> Option<ObservationState> {
    let mut open_ports = Vec::new();
    let mut reachable = false;
    for &port in ports {
        let addr = SocketAddr::new(host, port);
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(_) => {
                reachable = true;
                open_ports.push(PortObservation {
                    port,
                    proto: "tcp".to_string(),
                    service: None,
                    version: None,
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => reachable = true,
            Err(_) => {}
        }
    }
    reachable.then_some(ObservationState { up: true, open_ports, os_guess: None })
}

fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    spec.split(',')
        .map(|p| p.trim().parse::<u16>().map_err(|_| format!("invalid port '{p}'")))
        .collect()
}
