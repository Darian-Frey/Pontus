//! `pontus-cli` — the Phase 1 driver and reference consumer of `pontus-core`
//! (F-005). Everything it does goes through the headless core: scope enforcement,
//! discovery, identity resolution and the append-only store all live there.

use clap::{Parser, Subcommand};
use ipnet::IpNet;
use pontus_core::discovery::{self, DiscoveredHost, Method};
use pontus_core::scan::{OpenPort, ScanConfig, scan_hosts};
use pontus_core::{IdentitySignals, ObservationState, PortObservation, Scope, Store};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::process::ExitCode;
use std::time::Duration;
use tokio::task::JoinSet;

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
    /// Diff two scans: opened/closed ports, new/vanished hosts, address moves.
    Diff {
        #[arg(long, default_value = "pontus.db")]
        db: String,
        /// Earlier scan id (defaults to the second-most-recent scan).
        #[arg(long)]
        from: Option<i64>,
        /// Later scan id (defaults to the most-recent scan).
        #[arg(long)]
        to: Option<i64>,
        /// Also list hosts that did not change.
        #[arg(long)]
        all: bool,
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
    /// TCP ports to scan on each live host (hybrid SYN sweep → connect deep pass).
    #[arg(long, default_value = "22,80,443,445,3389,8080")]
    ports: String,
    /// How long the stateless SYN sweep listens for SYN-ACKs, milliseconds.
    #[arg(long, default_value_t = 800)]
    sweep_timeout_ms: u64,
    /// Per-port connect timeout in the deep pass, milliseconds.
    #[arg(long, default_value_t = 400)]
    timeout_ms: u64,
    /// How long to wait for a service banner after connecting, milliseconds.
    #[arg(long, default_value_t = 500)]
    banner_timeout_ms: u64,
    /// Skip reverse-DNS resolution of discovered hosts.
    #[arg(long)]
    no_rdns: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Scan(args) => run_scan(args).await,
        Command::Assets { db } => list_assets(&db),
        Command::Diff { db, from, to, all } => run_diff(&db, from, to, all),
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

    // Port-scan the live hosts (hybrid: stateless SYN sweep → stateful deep pass).
    let live_ips: Vec<IpAddr> = hosts.iter().map(|h| h.ip).collect();
    let cfg = ScanConfig {
        ports,
        sweep_wait: Duration::from_millis(args.sweep_timeout_ms),
        connect_timeout: port_timeout,
        banner_wait: Duration::from_millis(args.banner_timeout_ms),
    };
    let scanned: HashMap<IpAddr, Vec<OpenPort>> = scan_hosts(&live_ips, &cfg)
        .await?
        .into_iter()
        .map(|hp| (hp.ip, hp.open))
        .collect();

    // Reverse-DNS the live hosts to populate the hostname identity tier (F-004).
    let hostnames = if args.no_rdns {
        HashMap::new()
    } else {
        resolve_hostnames(&live_ips).await
    };

    let mut up = 0u64;
    for host in &hosts {
        let open = scanned.get(&host.ip).cloned().unwrap_or_default();
        let hostname = hostnames.get(&host.ip).cloned();
        // Resolve to a durable asset (ARP-discovered hosts carry a MAC — the
        // strongest identity signal, F-004) and append one observation.
        let observed_ports = open
            .iter()
            .map(|p| PortObservation {
                port: p.port,
                proto: p.proto.to_string(),
                // Banner kept as an interim service hint pending the Detector (Phase 3).
                service: p.banner.clone(),
                version: None,
            })
            .collect();
        let state = ObservationState { up: true, open_ports: observed_ports, os_guess: None };
        let sig = IdentitySignals {
            mac: host.mac.map(|m| m.to_string()),
            hostname: hostname.clone(),
            ip: Some(host.ip),
            ..Default::default()
        };
        store.record(&sig, scan_id, &state)?;
        up += 1;
        println!(
            "  up: {:<39}  {:<4}  {:<17}  {:<24}  ports: {}",
            host.ip,
            host.method.as_str(),
            mac_label(host),
            hostname.as_deref().unwrap_or("-"),
            render_ports(&open),
        );
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
        "{:>4}  {:<9}  {:<24}  {:<24}  {:<16}  {:>4}  LAST SEEN",
        "ID", "ANCHOR", "IDENTITY", "HOSTNAME", "LAST IP", "OBS"
    );
    for a in assets {
        println!(
            "{:>4}  {:<9}  {:<24}  {:<24}  {:<16}  {:>4}  {}",
            a.id,
            a.identity_kind,
            a.identity_value,
            a.hostname.as_deref().unwrap_or("-"),
            a.last_ip.as_deref().unwrap_or("-"),
            a.observations,
            a.last_seen,
        );
    }
    Ok(())
}

fn run_diff(db: &str, from: Option<i64>, to: Option<i64>, all: bool) -> Result<(), Box<dyn std::error::Error>> {
    use pontus_core::diff::{HostStatus, diff_observations};

    let store = Store::open(db)?;

    // Default to the two most recent scans when ids aren't given.
    let (from_id, to_id) = match (from, to) {
        (Some(f), Some(t)) => (f, t),
        _ => {
            let recent = store.recent_scans(2)?;
            if recent.len() < 2 {
                return Err("need at least two scans to diff (run another scan first)".into());
            }
            (recent[1].id, recent[0].id) // recent[0] is newest
        }
    };

    let from_scan = store.scan(from_id)?.ok_or_else(|| format!("no scan with id {from_id}"))?;
    let to_scan = store.scan(to_id)?.ok_or_else(|| format!("no scan with id {to_id}"))?;
    let diffs = diff_observations(
        &store.observations_for_scan(from_id)?,
        &store.observations_for_scan(to_id)?,
    );

    println!(
        "diff: scan {} ({}) → scan {} ({})",
        from_scan.id, from_scan.started_at, to_scan.id, to_scan.started_at
    );

    let (mut new, mut gone, mut changed, mut same) = (0u32, 0u32, 0u32, 0u32);
    for d in &diffs {
        let tag = match d.status {
            HostStatus::New => {
                new += 1;
                "NEW"
            }
            HostStatus::Vanished => {
                gone += 1;
                "GONE"
            }
            HostStatus::Changed => {
                changed += 1;
                "CHANGED"
            }
            HostStatus::Unchanged => {
                same += 1;
                "---"
            }
        };
        if d.status == HostStatus::Unchanged && !all {
            continue;
        }
        let mut notes = Vec::new();
        if let Some(prev) = &d.moved_from {
            notes.push(format!("moved {prev} → {}", d.ip));
        }
        if !d.opened.is_empty() {
            notes.push(format!("+{}", join_ports(&d.opened)));
        }
        if !d.closed.is_empty() {
            notes.push(format!("-{}", join_ports(&d.closed)));
        }
        println!(
            "  [{:<7}] {:<9} {:<24} {:<16} {}",
            tag,
            d.identity_kind,
            d.identity_value,
            d.ip,
            notes.join("  "),
        );
    }
    println!("summary: {new} new, {gone} vanished, {changed} changed, {same} unchanged");
    Ok(())
}

fn join_ports(ports: &[u16]) -> String {
    ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")
}

/// Reverse-DNS every live IP concurrently (each lookup is blocking, so it runs on
/// the blocking pool). Returns only the hosts that resolved.
async fn resolve_hostnames(ips: &[IpAddr]) -> HashMap<IpAddr, String> {
    let mut set = JoinSet::new();
    for &ip in ips {
        set.spawn_blocking(move || (ip, pontus_core::rdns::reverse_lookup(ip)));
    }
    let mut map = HashMap::new();
    while let Some(res) = set.join_next().await {
        if let Ok((ip, Some(name))) = res {
            map.insert(ip, name);
        }
    }
    map
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

/// Render open ports for the console, annotating with a short banner where present.
fn render_ports(open: &[OpenPort]) -> String {
    if open.is_empty() {
        return "-".to_string();
    }
    open.iter()
        .map(|p| match &p.banner {
            Some(b) if !b.is_empty() => format!("{}({})", p.port, truncate(b, 24)),
            _ => p.port.to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() > n {
        format!("{}…", s.chars().take(n).collect::<String>())
    } else {
        s.to_string()
    }
}

fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    spec.split(',')
        .map(|p| p.trim().parse::<u16>().map_err(|_| format!("invalid port '{p}'")))
        .collect()
}
