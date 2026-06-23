//! `pontus-cli` — the Phase 1 driver and reference consumer of `pontus-core`
//! (F-005). Everything it does goes through the headless core: scope enforcement,
//! discovery, identity resolution and the append-only store all live there.

use clap::{Parser, Subcommand};
use ipnet::IpNet;
use pontus_core::discovery::{self, DiscoveredHost, Method};
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
    /// Discover live hosts in a target range and record assets + observations.
    Scan(ScanArgs),
    /// List the assets currently in the store.
    Assets {
        #[arg(long, default_value = "pontus.db")]
        db: String,
    },
}

#[derive(Parser)]
struct ScanArgs {
    /// Target range, e.g. 192.168.1.0/24 or a single host (IPv4 or IPv6).
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
    /// How long discovery listens for replies, milliseconds.
    #[arg(long, default_value_t = 1000)]
    discovery_timeout_ms: u64,
    /// TCP ports probed to enrich a discovered host with open-port hints (interim,
    /// pending the F-002 stateful pass).
    #[arg(long, default_value = "22,80,443,445,3389,8080")]
    ports: String,
    /// Per-port connect timeout, milliseconds.
    #[arg(long, default_value_t = 400)]
    timeout_ms: u64,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Scan(args) => run_scan(args).await,
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

async fn run_scan(args: ScanArgs) -> Result<(), Box<dyn std::error::Error>> {
    // Scope is built and validated before anything else happens.
    let scope = Scope::parse(&args.scope)?;
    let targets: IpNet = pontus_core::scope::parse_cidr_or_host(&args.targets)?;
    let ports = parse_ports(&args.ports)?;
    let port_timeout = Duration::from_millis(args.timeout_ms);
    let discovery_timeout = Duration::from_millis(args.discovery_timeout_ms);

    // Expand the range and drop anything outside scope *before* a packet is sent
    // (F-007); count the refusals for the audit summary.
    let mut in_scope: Vec<IpAddr> = Vec::new();
    let mut refused = 0u64;
    for host in targets.hosts() {
        if scope.contains(host) {
            in_scope.push(host);
        } else {
            refused += 1;
        }
    }

    let store = Store::open(&args.db)?;
    let scan_id = store.begin_scan(&args.targets, &scope.to_string(), args.operator.as_deref())?;
    println!("scope: {scope}");
    println!("scan {scan_id}: discovering {} ({} host(s) in scope) ...", args.targets, in_scope.len());

    // Real discovery first; fall back to an unprivileged TCP probe if we lack
    // CAP_NET_RAW, so the tool still works without elevation.
    let hosts = match discovery::discover(&in_scope, discovery_timeout).await {
        Ok(hosts) => hosts,
        Err(e) if e.is_privilege() => {
            eprintln!("note: {e}");
            eprintln!("      falling back to unprivileged TCP-connect discovery");
            tcp_fallback(&in_scope, &ports, port_timeout)
        }
        Err(e) => return Err(e.into()),
    };

    let mut up = 0u64;
    for host in &hosts {
        // Enrich the liveness result with open-port hints (interim) and resolve to
        // a durable asset. ARP-discovered hosts carry a MAC — the strongest
        // identity signal (F-004).
        let mut state = probe(host.ip, &ports, port_timeout).unwrap_or_default();
        state.up = true;
        let sig = IdentitySignals {
            mac: host.mac.map(|m| m.to_string()),
            ip: Some(host.ip),
            ..Default::default()
        };
        store.record(&sig, scan_id, &state)?;
        up += 1;
        println!("  up: {:<39}  {:<4}  {}", host.ip, host.method.as_str(), mac_label(host));
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

fn mac_label(host: &DiscoveredHost) -> String {
    host.mac.map(|m| m.to_string()).unwrap_or_else(|| "-".to_string())
}

/// Unprivileged discovery fallback: a TCP connect "ping" over the probe ports.
/// Yields IP-only hosts (no MAC), used only when raw sockets are unavailable.
fn tcp_fallback(targets: &[IpAddr], ports: &[u16], timeout: Duration) -> Vec<DiscoveredHost> {
    targets
        .iter()
        .filter(|&&ip| probe(ip, ports, timeout).is_some())
        .map(|&ip| DiscoveredHost::new(ip, None, Method::TcpConnect))
        .collect()
}

/// A TCP connect probe: a successful connect *or* a connection-refused both prove
/// reachability; a timeout is treated as no answer. Open ports are returned as
/// interim service hints pending the raw-socket stateful pass (F-002).
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
