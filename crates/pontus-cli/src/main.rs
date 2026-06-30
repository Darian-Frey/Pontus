//! `pontus-cli` — the Phase 1 driver and reference consumer of `pontus-core`
//! (F-005). Everything it does goes through the headless core: scope enforcement,
//! discovery, identity resolution and the append-only store all live there.

use clap::{Parser, Subcommand, ValueEnum};
use ipnet::IpNet;
use pontus_core::discovery::{self, DiscoveredHost, Method};
use pontus_core::scan::udp::{self, UdpConfig, UdpState};
use pontus_core::os::{self, OsCorpus};
use pontus_core::scan::{HostPorts, OpenPort, ScanConfig, scan_hosts};
use pontus_core::traceroute;
use pontus_core::{
    Detector, IdentitySignals, KevCatalog, NativeDetector, NmapDetector, ObservationState,
    PortObservation, PortProbe, Scope, Store, StoredFinding, Vuln,
};
use pontus_plugins::{Language, NetCapabilities, Plugin, PluginHost};
use std::collections::HashMap;
use std::path::Path;
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
    /// Show hosts ranked by vulnerability risk (fix-first order) for a scan.
    Risk {
        #[arg(long, default_value = "pontus.db")]
        db: String,
        /// Scan id (defaults to the most recent).
        #[arg(long)]
        scan: Option<i64>,
    },
    /// List plugin findings recorded by a scan (F-020).
    Findings {
        #[arg(long, default_value = "pontus.db")]
        db: String,
        /// Scan id (defaults to the most recent).
        #[arg(long)]
        scan: Option<i64>,
    },
    /// List installed packages gathered by a credentialed scan (F-022).
    Packages {
        #[arg(long, default_value = "pontus.db")]
        db: String,
        /// Scan id (defaults to the most recent).
        #[arg(long)]
        scan: Option<i64>,
    },
    /// Export a scan as JSON, SARIF 2.1 or CSV (F-023).
    Export {
        #[arg(long, default_value = "pontus.db")]
        db: String,
        /// Scan id (defaults to the most recent).
        #[arg(long)]
        scan: Option<i64>,
        /// Output format.
        #[arg(long, value_enum, default_value_t = ExportFormat::Json)]
        format: ExportFormat,
        /// Write to this file instead of stdout.
        #[arg(long, short = 'o', value_name = "PATH")]
        output: Option<String>,
    },
    /// Manage cached vulnerability intelligence (CISA KEV, EPSS).
    Intel {
        #[command(subcommand)]
        command: IntelCommand,
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
    /// Inspect a host's TLS/SSL: protocols, cipher suites and certificate (F-016).
    Tls(TlsArgs),
    /// Identify the web technology stack of an HTTP(S) endpoint (F-017).
    Http(HttpArgs),
    /// Gather installed-package inventory from a host over SSH with user-supplied
    /// credentials (F-022). Scope-enforced; records packages against the asset.
    SshInventory(SshInventoryArgs),
    /// Show this machine's own network configuration: interfaces and listening ports (F-036).
    Netinfo,
}

#[derive(Parser)]
struct HttpArgs {
    /// Target host (IP or hostname) to fingerprint; the hostname is used for SNI.
    target: String,
    /// Authorised scope (repeatable). Mandatory — nothing is contacted outside it
    /// (F-007). Defaults to the target itself when omitted.
    #[arg(long = "scope", value_name = "CIDR|IP")]
    scope: Vec<String>,
    /// Port to fetch (443 → https, otherwise http).
    #[arg(long, default_value_t = 443)]
    port: u16,
    /// Web-tech signature corpus (JSON) layered over the built-in defaults (F-017).
    #[arg(long, value_name = "PATH")]
    web_corpus: Option<String>,
    /// Request timeout, milliseconds.
    #[arg(long, default_value_t = 6000)]
    timeout_ms: u64,
}

#[derive(Parser)]
struct TlsArgs {
    /// Target host (IP or hostname) to inspect; the hostname is also used for SNI.
    target: String,
    /// Authorised scope (repeatable). Mandatory — nothing is contacted outside it
    /// (F-007). Defaults to the target itself when omitted.
    #[arg(long = "scope", value_name = "CIDR|IP")]
    scope: Vec<String>,
    /// Port to inspect.
    #[arg(long, default_value_t = 443)]
    port: u16,
    /// Per-probe connect/read timeout, milliseconds.
    #[arg(long, default_value_t = 4000)]
    timeout_ms: u64,
}

#[derive(Parser)]
struct SshInventoryArgs {
    /// Target host (IP or hostname) to log in to.
    target: String,
    /// SSH username (required). Credentials are always user-supplied (F-022).
    #[arg(long)]
    user: String,
    /// Authorised scope (repeatable). Mandatory — nothing is contacted outside it
    /// (F-007). Defaults to the target itself when omitted.
    #[arg(long = "scope", value_name = "CIDR|IP")]
    scope: Vec<String>,
    /// SSH port.
    #[arg(long, default_value_t = 22)]
    port: u16,
    /// Private key file for key auth (otherwise the agent / default keys are used).
    #[arg(long, value_name = "PATH")]
    key: Option<String>,
    /// Use password auth, reading the password from the PONTUS_SSH_PASSWORD
    /// environment variable (needs `sshpass`). Never pass passwords on the CLI.
    #[arg(long)]
    password: bool,
    /// Require the host to already be in known_hosts (StrictHostKeyChecking=yes)
    /// instead of trusting on first use (accept-new).
    #[arg(long)]
    strict_host_keys: bool,
    /// Connect timeout, seconds.
    #[arg(long, default_value_t = 10)]
    connect_timeout_s: u64,
    /// Match installed packages to CVEs and enrich with EPSS/KEV (F-015), version-
    /// accurate from the *installed* versions. Hits the network (NVD/EPSS). Bounded
    /// to a built-in set of common network-service products unless --assess-packages
    /// is given. Best run after `intel update`.
    #[arg(long)]
    assess_vulns: bool,
    /// Comma-separated package names to assess against CVEs (overrides the built-in
    /// set); only those found in the inventory are looked up. Implies --assess-vulns.
    #[arg(long, value_name = "NAMES")]
    assess_packages: Option<String>,
    /// Store path.
    #[arg(long, default_value = "pontus.db")]
    db: String,
    /// Operator name, recorded in the audit log.
    #[arg(long)]
    operator: Option<String>,
}

#[derive(Subcommand)]
enum IntelCommand {
    /// Fetch and cache the CISA Known Exploited Vulnerabilities catalogue.
    Update {
        /// Cache directory (default: $XDG_CACHE_HOME/pontus or ~/.cache/pontus).
        #[arg(long)]
        cache: Option<String>,
    },
    /// Show the cached intelligence status.
    Status {
        #[arg(long)]
        cache: Option<String>,
    },
}

/// Output format for `export` (F-023).
#[derive(Clone, Copy, Debug, ValueEnum)]
enum ExportFormat {
    /// Pontus-native JSON (lossless).
    Json,
    /// SARIF 2.1 (findings for CI / code-scanning).
    Sarif,
    /// CSV inventory (one row per host).
    Csv,
}

/// Which service detector to run over scan results.
#[derive(Clone, Copy, Debug, ValueEnum)]
enum DetectorKind {
    /// The built-in clean-room detector (banner grammar + well-known ports).
    Native,
    /// Shell out to the user's own installed `nmap -sV` (D-006).
    Nmap,
}

/// Which OS detector to use (F-013, D-011).
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum OsDetectorKind {
    /// The built-in passive corpus (TCP-stack signature + TTL + banners).
    Native,
    /// Shell out to the user's own `nmap -O` for a version-range guess. Needs
    /// raw-socket privilege, so run pontus-cli via sudo.
    Nmap,
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
    /// Accepts single ports, ranges and `-` for all: `80,443,8000-8100`, `1-1024`, `-`.
    #[arg(long, default_value = "22,80,443,445,3389,8080")]
    ports: String,
    /// Also scan the N most common TCP service ports (a curated preset). Unioned
    /// with `--ports`; e.g. `--top-ports 1000`.
    #[arg(long, value_name = "N")]
    top_ports: Option<u16>,
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
    /// Service detector: the native clean-room detector, or shell out to your own nmap.
    #[arg(long, value_enum, default_value_t = DetectorKind::Native)]
    detector: DetectorKind,
    /// Match detected services to CVEs and enrich with EPSS + KEV (F-015). Hits the
    /// network (NVD/EPSS) and is best run after `intel update`.
    #[arg(long)]
    assess_vulns: bool,
    /// OS detector: the passive built-in corpus, or shell out to your own `nmap -O`
    /// for a version-range guess (needs sudo). Default: native.
    #[arg(long, value_enum, default_value_t = OsDetectorKind::Native)]
    os_detector: OsDetectorKind,
    /// OS fingerprint corpus (JSON) layered over the built-in clean-room defaults,
    /// so signatures can be added without a rebuild (F-013).
    #[arg(long, value_name = "PATH")]
    os_corpus: Option<String>,
    /// Web-tech signature corpus (JSON) layered over the built-in defaults, for
    /// `--inspect` (F-017).
    #[arg(long, value_name = "PATH")]
    web_corpus: Option<String>,
    /// Deep-inspect open TLS/HTTP ports: TLS protocols/ciphers/cert (F-016) and
    /// web technology stack (F-017), recorded on the observation. Adds handshakes
    /// and requests, so it is opt-in.
    #[arg(long)]
    inspect: bool,
    /// Per-endpoint timeout for `--inspect`, milliseconds.
    #[arg(long, default_value_t = 5000)]
    inspect_timeout_ms: u64,
    /// Skip the traceroute / topology pass.
    #[arg(long)]
    no_traceroute: bool,
    /// Maximum traceroute hops per host.
    #[arg(long, default_value_t = 30)]
    max_hops: u8,
    /// Per-hop traceroute wait, milliseconds.
    #[arg(long, default_value_t = 500)]
    trace_timeout_ms: u64,
    /// UDP ports to scan on each live host (off by default). Reports open and
    /// open|filtered; closed ports (ICMP-unreachable) are omitted.
    #[arg(long, value_name = "PORTS")]
    udp_ports: Option<String>,
    /// Per-port UDP wait for a reply, milliseconds.
    #[arg(long, default_value_t = 1000)]
    udp_timeout_ms: u64,
    /// UDP probe retries (UDP is lossy; a retry cuts false open|filtered).
    #[arg(long, default_value_t = 1)]
    udp_retries: u8,
    /// Directory of plugins to run against each scanned host (F-020). Files are
    /// dispatched by extension: `.lua`, `.wasm`/`.wat`, and `.py` (the last needs
    /// a `--features python` build). Findings are recorded against the asset.
    #[arg(long, value_name = "DIR")]
    plugins: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Scan(args) => run_scan(args).await,
        Command::Assets { db } => list_assets(&db),
        Command::Intel { command } => run_intel(command),
        Command::Risk { db, scan } => run_risk(&db, scan),
        Command::Findings { db, scan } => run_findings(&db, scan),
        Command::Packages { db, scan } => run_packages(&db, scan),
        Command::Export { db, scan, format, output } => run_export(&db, scan, format, output),
        Command::Diff { db, from, to, all } => run_diff(&db, from, to, all),
        Command::Tls(args) => run_tls(args),
        Command::Http(args) => run_http(args),
        Command::SshInventory(args) => run_ssh_inventory(args),
        Command::Netinfo => run_netinfo(),
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
    let ports = resolve_ports(&args.ports, args.top_ports)?;
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
    let scanned: HashMap<IpAddr, HostPorts> = scan_hosts(&live_ips, &cfg)
        .await?
        .into_iter()
        .map(|hp| (hp.ip, hp))
        .collect();

    // Reverse-DNS the live hosts to populate the hostname identity tier (F-004).
    let hostnames = if args.no_rdns {
        HashMap::new()
    } else {
        resolve_hostnames(&live_ips).await
    };

    // Optional UDP pass over the live hosts.
    let udp_ports = match &args.udp_ports {
        Some(spec) => parse_ports(spec)?,
        None => Vec::new(),
    };
    let udp_cfg = UdpConfig {
        timeout: Duration::from_millis(args.udp_timeout_ms),
        retries: args.udp_retries,
    };

    let detector: Box<dyn Detector> = match args.detector {
        DetectorKind::Native => Box::new(NativeDetector),
        DetectorKind::Nmap => Box::new(NmapDetector::new()),
    };

    // OS detector (F-013, D-011): the passive corpus by default, or a shell-out to
    // the user's own `nmap -O`. The corpus (built-in defaults plus an optional user
    // file) feeds the native path.
    let os_corpus = match &args.os_corpus {
        Some(path) => OsCorpus::load(path)?,
        None => OsCorpus::builtin(),
    };
    let os_detector: Box<dyn os::OsDetector> = match args.os_detector {
        OsDetectorKind::Native => Box::new(os::NativeOsDetector::new(os_corpus)),
        OsDetectorKind::Nmap => Box::new(os::NmapOsDetector::new()),
    };

    // Web-tech corpus for `--inspect` (F-017): built-in defaults plus an optional
    // user file (IMP-011).
    let web_corpus = match &args.web_corpus {
        Some(path) => pontus_core::WebCorpus::load(path)?,
        None => pontus_core::WebCorpus::builtin(),
    };
    if args.os_detector == OsDetectorKind::Nmap {
        println!("note: --os-detector nmap runs `nmap -O` per host, which needs root — run via sudo");
    }

    // Vulnerability assessment (F-015) is opt-in: it hits the network. Load the
    // cached KEV catalogue and dedupe CVE lookups by (product, version) per scan.
    let kev = if args.assess_vulns { load_kev_cache() } else { KevCatalog::default() };
    let mut vuln_cache: HashMap<(String, Option<String>), Vec<Vuln>> = HashMap::new();

    // Load plugins (F-020). Built once; run against each up host below. An empty
    // set (no --plugins) skips the whole pass.
    let plugin_host = build_plugin_host();
    let plugins = match &args.plugins {
        Some(dir) => load_plugins(dir),
        None => Vec::new(),
    };
    if !plugins.is_empty() {
        println!("plugins: {} loaded from {}", plugins.len(), args.plugins.as_deref().unwrap_or(""));
    }
    // Host capabilities for probing plugins (F-021): a scope-enforced HTTP fetch.
    // The predicate gates every request by the scan's scope (F-007), so a plugin
    // can only reach hosts already authorised for this scan.
    let plugin_caps = {
        let scope = scope.clone();
        NetCapabilities::new(move |ip| scope.contains(ip), Duration::from_millis(args.inspect_timeout_ms))
    };

    let mut up = 0u64;
    let mut os_guessed = 0u64;
    for host in &hosts {
        let host_ports = scanned.get(&host.ip);
        let open: Vec<OpenPort> = host_ports.map(|hp| hp.open.clone()).unwrap_or_default();
        let hostname = hostnames.get(&host.ip).cloned();

        // Identify services on the open ports (F-012) so observations carry
        // structured service/version rather than a raw banner.
        let probes: Vec<PortProbe> = open
            .iter()
            .map(|p| PortProbe { port: p.port, proto: p.proto.to_string(), banner: p.banner.clone() })
            .collect();
        let services = detector.detect(host.ip, &probes);
        let mut observed_ports: Vec<PortObservation> = open
            .iter()
            .map(|p| {
                let service = services.get(&p.port);
                PortObservation {
                    port: p.port,
                    proto: p.proto.to_string(),
                    service: service.map(|s| s.name.clone()),
                    version: service.and_then(|s| s.version_string()),
                    ..Default::default()
                }
            })
            .collect();

        // UDP pass: record open and open|filtered (closed is omitted).
        let udp_results = if udp_ports.is_empty() {
            Vec::new()
        } else {
            udp::scan_host(host.ip, &udp_ports, &udp_cfg).await
        };
        for r in &udp_results {
            if r.state == UdpState::Closed {
                continue;
            }
            observed_ports.push(PortObservation {
                port: r.port,
                proto: "udp".to_string(),
                service: r.response.clone().or_else(|| Some(r.state.as_str().to_string())),
                version: None,
                ..Default::default()
            });
        }

        // Deep inspection (F-016/F-017): on open TLS/HTTP ports, inspect TLS and
        // fingerprint the web stack, attaching the findings to the port observation.
        // Opt-in — it adds handshakes/requests — and uses the resolved hostname for
        // SNI / the request URL where available.
        if args.inspect {
            let sni = hostname.clone().unwrap_or_default();
            let url_host = hostname.clone().unwrap_or_else(|| host.ip.to_string());
            let timeout = Duration::from_millis(args.inspect_timeout_ms);
            for po in observed_ports.iter_mut().filter(|p| p.proto == "tcp") {
                let addr = std::net::SocketAddr::new(host.ip, po.port);
                if matches!(po.port, 443 | 8443) {
                    let report = pontus_core::tls::inspect(addr, &sni, timeout);
                    po.tls = Some(tls_to_obs(&report));
                }
                if matches!(po.port, 80 | 443 | 8080 | 8000 | 8443) {
                    let scheme = if matches!(po.port, 443 | 8443) { "https" } else { "http" };
                    let url = format!("{scheme}://{url_host}:{}/", po.port);
                    if let Ok(fp) = pontus_core::webtech::fingerprint(&url, &web_corpus, timeout) {
                        po.tech = fp.techs.iter().map(tech_to_obs).collect();
                    }
                }
            }
        }

        // OS guess from the chosen detector (F-013). The native path scores the
        // SYN-ACK stack signature (TTL, window, DF, TCP option layout) and banners,
        // falling back to the ICMP echo-reply TTL for portless hosts (IMP-006); the
        // nmap path ignores these and probes the host itself.
        let os_guess = {
            let stack = host_ports.map(|hp| &hp.stack);
            let banners = host_ports
                .map(|hp| hp.open.iter().filter_map(|p| p.banner.clone()).collect())
                .unwrap_or_default();
            let sig = os::OsSignals {
                ttl: stack.and_then(|s| s.ttl).or(host.ttl),
                tcp_window: stack.and_then(|s| s.window),
                df: stack.and_then(|s| s.df),
                opts_layout: stack.and_then(|s| s.opts_layout.clone()),
                banners,
            };
            os_detector.detect(host.ip, &sig)
        };
        if os_guess.is_some() {
            os_guessed += 1;
        }

        // Resolve to a durable asset (ARP-discovered hosts carry a MAC — the
        // strongest identity signal, F-004) and append one observation.
        let state = ObservationState {
            up: true,
            open_ports: observed_ports,
            os_guess: os_guess.as_ref().map(|g| g.label()),
        };
        let sig = IdentitySignals {
            mac: host.mac.map(|m| m.to_string()),
            hostname: hostname.clone(),
            ip: Some(host.ip),
            ..Default::default()
        };
        let asset_id = store.record(&sig, scan_id, &state)?;
        up += 1;

        // Match detected products to CVEs and enrich (F-015). Products come from
        // two sources, deduped: the service detector, and — so the clean-room
        // native detector + `--inspect` yields CVEs without nmap (IMP-015) — the
        // web-tech fingerprints attached to each port. Each assessment is reported,
        // so a "no vulns" outcome isn't silent.
        if args.assess_vulns {
            let mut targets: Vec<(String, Option<String>, u16)> = Vec::new();
            for (port, service) in &services {
                if let Some(product) = &service.product {
                    targets.push((product.clone(), service.version.clone(), *port));
                }
            }
            for po in &state.open_ports {
                for t in &po.tech {
                    targets.push((t.name.clone(), t.version.clone(), po.port));
                }
            }
            for (product, version, port) in targets {
                let vulns = vuln_cache.entry((product.clone(), version.clone())).or_insert_with(|| {
                    match pontus_core::intel::assess(&product, version.as_deref(), &kev) {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("note: vuln assessment for {product} failed: {e}");
                            Vec::new()
                        }
                    }
                });
                let ver = version.as_deref().unwrap_or("(no version)");
                println!("       vulns {port}: {product} {ver} → {} CVE(s)", vulns.len());
                // record_vuln uses INSERT OR IGNORE on (scan, asset, port, cve), so a
                // CVE found via both the detector and web-tech is stored once.
                for v in vulns.iter() {
                    store.record_vuln(scan_id, asset_id, port, v)?;
                }
            }
        }

        // Plugin pass (F-020): build a target from this host's observation and run
        // every loaded plugin, persisting findings against the asset. A plugin error
        // is reported but never aborts the scan.
        if !plugins.is_empty() {
            let target = build_target(host, hostname.as_deref(), &state.open_ports);
            for plugin in &plugins {
                match plugin_host.run_with(plugin, &target, &plugin_caps) {
                    Ok(findings) => {
                        for f in &findings {
                            store.record_finding(scan_id, &to_stored(f, asset_id))?;
                        }
                        for f in &findings {
                            println!("      plugin {}: [{}] {}", plugin.name, f.severity, f.title);
                        }
                    }
                    Err(e) => eprintln!("note: plugin {} on {}: {e}", plugin.name, host.ip),
                }
            }
        }

        println!(
            "  up: {:<39}  {:<4}  {:<17}  {:<24}  ports: {}",
            host.ip,
            host.method.as_str(),
            mac_label(host),
            hostname.as_deref().unwrap_or("-"),
            render_ports(&open),
        );
        let udp_shown = render_udp(&udp_results);
        if !udp_shown.is_empty() {
            println!("         udp: {udp_shown}");
        }
        if let Some(g) = &os_guess {
            println!("          os: {} ({:.0}% — {})", g.label(), g.confidence * 100.0,
                     g.evidence.join(", "));
        }
        // Show the raw SYN-ACK stack signature when captured, so an unrecognised
        // option layout is visible and can be turned into an --os-corpus rule (F-013).
        if let Some(stack) = host_ports.map(|hp| &hp.stack)
            && stack.opts_layout.is_some()
        {
            println!(
                "       stack: opts={}  window={}  df={}",
                stack.opts_layout.as_deref().unwrap_or("-"),
                stack.window.map_or("-".to_string(), |w| w.to_string()),
                stack.df.map_or("-", |d| if d { "set" } else { "clear" }),
            );
        }
        // Deep-inspection findings recorded on the ports this scan (F-016/F-017).
        for po in &state.open_ports {
            if let Some(tls) = &po.tls
                && !tls.findings.is_empty()
            {
                println!("         tls {}: {}", po.port, tls.findings.join("; "));
            }
            if !po.tech.is_empty() {
                let names: Vec<String> = po
                    .tech
                    .iter()
                    .map(|t| t.version.as_ref().map_or_else(|| t.name.clone(), |v| format!("{} {v}", t.name)))
                    .collect();
                println!("         web {}: {}", po.port, names.join(", "));
            }
        }
    }
    // `nmap -O` returning nothing for every host usually means it lacked privilege.
    if args.os_detector == OsDetectorKind::Nmap && up > 0 && os_guessed == 0 {
        eprintln!(
            "note: nmap produced no OS match for any host — `nmap -O` needs root; \
             re-run pontus-cli via sudo, and ensure nmap is installed"
        );
    }

    // Topology pass: traceroute each live host and record path edges (F-009).
    let mut edges = 0u64;
    if !args.no_traceroute {
        let trace_wait = Duration::from_millis(args.trace_timeout_ms);
        let mut privileged = true;
        for host in &hosts {
            if !privileged {
                break;
            }
            let scanner = traceroute::egress_source(host.ip);
            match traceroute::trace(host.ip, args.max_hops, trace_wait).await {
                Ok(hops) => {
                    let mut prev = scanner;
                    for hop in hops {
                        if let Some(ip) = hop.ip {
                            if let Some(p) = prev {
                                if p != ip {
                                    store.record_edge(scan_id, &p.to_string(), &ip.to_string())?;
                                    edges += 1;
                                }
                            }
                            prev = Some(ip);
                        }
                    }
                }
                Err(e) if e.is_privilege() => {
                    eprintln!("note: {e}");
                    eprintln!("      skipping topology (traceroute needs CAP_NET_RAW)");
                    privileged = false;
                }
                Err(_) => {}
            }
        }
    }

    store.finish_scan(scan_id)?;
    println!(
        "done: {up} host(s) up, {refused} target(s) refused as out-of-scope; \
         {} asset(s), {} observation(s), {edges} edge(s) total",
        store.asset_count()?,
        store.observation_count()?
    );
    if args.assess_vulns {
        print_risk(&store, scan_id)?;
    }
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

fn run_intel(command: IntelCommand) -> Result<(), Box<dyn std::error::Error>> {
    use pontus_core::intel::{KevCatalog, fetch_kev_json};
    match command {
        IntelCommand::Update { cache } => {
            let path = kev_cache_path(cache);
            println!("Fetching CISA KEV catalogue…");
            let json = fetch_kev_json()?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, &json)?;
            let catalogue = KevCatalog::from_json(&json)?;
            println!(
                "KEV updated: {} known-exploited CVEs cached at {}",
                catalogue.len(),
                path.display()
            );
        }
        IntelCommand::Status { cache } => {
            let path = kev_cache_path(cache);
            match std::fs::read_to_string(&path) {
                Ok(json) => {
                    let catalogue = KevCatalog::from_json(&json)?;
                    println!("KEV cache: {} CVEs at {}", catalogue.len(), path.display());
                }
                Err(_) => println!(
                    "No KEV cache at {} — run `pontus-cli intel update`",
                    path.display()
                ),
            }
        }
    }
    Ok(())
}

/// Load the cached KEV catalogue (from `intel update`), or an empty one with a note.
fn load_kev_cache() -> KevCatalog {
    let path = kev_cache_path(None);
    match std::fs::read_to_string(&path).ok().and_then(|j| KevCatalog::from_json(&j).ok()) {
        Some(catalogue) => catalogue,
        None => {
            eprintln!(
                "note: no KEV cache at {} — run `pontus-cli intel update` for KEV enrichment",
                path.display()
            );
            KevCatalog::default()
        }
    }
}

fn run_risk(db: &str, scan: Option<i64>) -> Result<(), Box<dyn std::error::Error>> {
    let store = Store::open(db)?;
    let scan_id = match scan {
        Some(id) => id,
        None => store
            .recent_scans(1)?
            .first()
            .map(|s| s.id)
            .ok_or("no scans in the store")?,
    };
    print_risk(&store, scan_id)?;
    Ok(())
}

/// List plugin findings recorded by a scan (F-020).
fn run_findings(db: &str, scan: Option<i64>) -> Result<(), Box<dyn std::error::Error>> {
    let store = Store::open(db)?;
    let scan_id = match scan {
        Some(id) => id,
        None => store
            .recent_scans(1)?
            .first()
            .map(|s| s.id)
            .ok_or("no scans in the store")?,
    };
    let findings = store.findings_for_scan(scan_id)?;
    if findings.is_empty() {
        println!("findings: none recorded for scan {scan_id}");
        return Ok(());
    }
    println!("findings for scan {scan_id}:");
    for f in &findings {
        let host = f.ip.as_deref().unwrap_or(&f.identity);
        println!("  [{:^8}] {:<24} {} — {}", f.severity, host, f.plugin, f.title);
        if !f.description.is_empty() {
            println!("             {}", f.description);
        }
    }
    Ok(())
}

/// Export a scan as JSON, SARIF 2.1 or CSV (F-023).
fn run_export(
    db: &str,
    scan: Option<i64>,
    format: ExportFormat,
    output: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let store = Store::open(db)?;
    let scan_id = match scan {
        Some(id) => id,
        None => store
            .recent_scans(1)?
            .first()
            .map(|s| s.id)
            .ok_or("no scans in the store")?,
    };
    let report = pontus_core::export::report(&store, scan_id)?;
    let text = match format {
        ExportFormat::Json => pontus_core::export::to_json(&report),
        ExportFormat::Sarif => pontus_core::export::to_sarif(&report),
        ExportFormat::Csv => pontus_core::export::to_csv(&report),
    };
    match output {
        Some(path) => {
            std::fs::write(&path, text)?;
            eprintln!("wrote {path}");
        }
        None => println!("{text}"),
    }
    Ok(())
}

/// List installed packages gathered by a credentialed scan (F-022).
fn run_packages(db: &str, scan: Option<i64>) -> Result<(), Box<dyn std::error::Error>> {
    let store = Store::open(db)?;
    let scan_id = match scan {
        Some(id) => id,
        None => store
            .recent_scans(1)?
            .first()
            .map(|s| s.id)
            .ok_or("no scans in the store")?,
    };
    let packages = store.packages_for_scan(scan_id)?;
    if packages.is_empty() {
        println!("packages: none recorded for scan {scan_id} (run `ssh-inventory`)");
        return Ok(());
    }
    println!("packages for scan {scan_id}: {} total", packages.len());
    for p in &packages {
        let host = p.ip.as_deref().unwrap_or(&p.identity);
        println!("  {:<24} {} {}", host, p.name, p.version);
    }
    Ok(())
}

/// Render hosts ranked by vulnerability risk (fix-first order, C-002).
fn print_risk(store: &Store, scan_id: i64) -> Result<(), Box<dyn std::error::Error>> {
    let hosts = store.risk_ranked(scan_id)?;
    if hosts.is_empty() {
        println!("\nrisk: no vulnerabilities recorded for scan {scan_id}");
        return Ok(());
    }

    println!("\nrisk (fix first):");
    for host in hosts {
        let top_desc = host
            .vulns
            .first()
            .map(|v| {
                let scope = if v.version_matched { "" } else { " (product-wide)" };
                format!("{} [{}]{}", v.cve_id, v.band, scope)
            })
            .unwrap_or_default();
        println!(
            "  {:>7.1}  {} {:<20} {:<16} {:>3} vuln(s)  top: {}",
            host.risk,
            host.identity_kind,
            host.identity_value,
            host.ip.as_deref().unwrap_or("-"),
            host.vulns.len(),
            top_desc
        );
    }
    Ok(())
}

fn kev_cache_path(cache: Option<String>) -> std::path::PathBuf {
    let dir = cache.map(std::path::PathBuf::from).unwrap_or_else(default_cache_dir);
    dir.join("kev.json")
}

fn default_cache_dir() -> std::path::PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
        return std::path::PathBuf::from(xdg).join("pontus");
    }
    // Privileged scans run under sudo (HOME=/root), but `intel update` is run as
    // the user — so prefer the invoking user's cache, where the catalogue actually
    // lives, rather than root's (BUG-008).
    if let Ok(user) = std::env::var("SUDO_USER") {
        let home = std::path::PathBuf::from("/home").join(&user);
        if home.is_dir() {
            return home.join(".cache").join("pontus");
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        return std::path::PathBuf::from(home).join(".cache").join("pontus");
    }
    std::path::PathBuf::from(".pontus-cache")
}

fn run_tls(args: TlsArgs) -> Result<(), Box<dyn std::error::Error>> {
    use std::net::ToSocketAddrs;

    // The hostname doubles as SNI; a bare IP target carries no SNI.
    let is_ip = args.target.parse::<IpAddr>().is_ok();
    let sni = if is_ip { String::new() } else { args.target.clone() };

    let addr = (args.target.as_str(), args.port)
        .to_socket_addrs()?
        .next()
        .ok_or("could not resolve target")?;

    // Scope enforcement (F-007): refuse before any packet. Defaults to the target.
    let scope_specs: Vec<String> =
        if args.scope.is_empty() { vec![addr.ip().to_string()] } else { args.scope.clone() };
    let scope = Scope::parse(&scope_specs)?;
    scope.ensure(addr.ip())?;

    println!("tls: {} ({}) port {}", args.target, addr.ip(), args.port);
    let report = pontus_core::tls::inspect(addr, &sni, Duration::from_millis(args.timeout_ms));
    print_tls_report(&report);
    Ok(())
}

fn run_ssh_inventory(args: SshInventoryArgs) -> Result<(), Box<dyn std::error::Error>> {
    use std::net::ToSocketAddrs;

    let is_ip = args.target.parse::<IpAddr>().is_ok();
    let addr = (args.target.as_str(), args.port)
        .to_socket_addrs()?
        .next()
        .ok_or("could not resolve target")?;

    // Scope enforcement (F-007): refuse before connecting. Defaults to the target.
    let scope_specs: Vec<String> =
        if args.scope.is_empty() { vec![addr.ip().to_string()] } else { args.scope.clone() };
    let scope = Scope::parse(&scope_specs)?;
    scope.ensure(addr.ip())?;

    // Password (if requested) comes from the environment, never the command line.
    let password = if args.password {
        Some(std::env::var("PONTUS_SSH_PASSWORD").map_err(|_| {
            "--password set but PONTUS_SSH_PASSWORD is not in the environment"
        })?)
    } else {
        None
    };

    let opts = pontus_core::SshOptions {
        user: args.user.clone(),
        port: args.port,
        identity_file: args.key.clone().map(std::path::PathBuf::from),
        password,
        connect_timeout: Duration::from_secs(args.connect_timeout_s.max(1)),
        accept_new_host_keys: !args.strict_host_keys,
    };

    println!("ssh-inventory: {}@{} ({}) ...", args.user, args.target, addr.ip());
    let inv = pontus_core::gather_ssh_inventory(&args.target, &opts)?;
    println!(
        "  os: {}   packages: {} ({})",
        inv.os.as_deref().unwrap_or("(unknown)"),
        inv.packages.len(),
        inv.manager.as_deref().unwrap_or("no package manager"),
    );

    // Record against the asset: one observation (SSH up, OS from the host) plus the
    // package inventory (F-022, D-007).
    let store = Store::open(&args.db)?;
    let scan_id = store.begin_scan(&args.target, &scope_specs.join(","), args.operator.as_deref())?;
    let state = ObservationState {
        up: true,
        open_ports: vec![PortObservation {
            port: args.port,
            proto: "tcp".to_string(),
            service: Some("ssh".to_string()),
            ..Default::default()
        }],
        os_guess: inv.os.clone(),
    };
    let sig = IdentitySignals {
        ip: Some(addr.ip()),
        hostname: (!is_ip).then(|| args.target.clone()),
        ..Default::default()
    };
    let asset_id = store.record(&sig, scan_id, &state)?;
    for p in &inv.packages {
        store.record_package(scan_id, asset_id, &p.name, &p.version)?;
    }
    println!("  recorded {} package(s) against asset {asset_id} (scan {scan_id})", inv.packages.len());

    // Credentialed CVE matching (F-022 + F-015): assess installed package versions
    // against NVD — far more accurate than network-banner detection. Bounded to a
    // selected set so a 2000-package host doesn't flood the NVD API.
    if args.assess_vulns || args.assess_packages.is_some() {
        assess_packages(&store, scan_id, asset_id, &inv, args.assess_packages.as_deref())?;
    }

    store.finish_scan(scan_id)?;
    Ok(())
}

/// A small, clean-room set of common network-service products that map cleanly to
/// NVD CPEs — the default selection for credentialed CVE matching when the user
/// gives no explicit `--assess-packages` list. (Distro-advisory/OVAL-based whole-
/// inventory matching is a larger future effort.)
const CRED_ASSESS_PRODUCTS: &[&str] = &[
    "openssh", "openssl", "nginx", "apache2", "httpd", "bind9", "bind", "dnsmasq",
    "samba", "vsftpd", "proftpd", "postfix", "exim4", "dovecot", "mariadb", "mysql",
    "postgresql", "redis", "mosquitto", "lighttpd", "haproxy", "squid", "sudo",
];

/// Normalise a distro package version to an upstream-ish version NVD can match:
/// strip a leading `epoch:` and a trailing `-revision` (Debian) or `-release`
/// (the `version-release` we collect from rpm). E.g. `1:8.9p1-3ubuntu0.10` → `8.9p1`.
fn normalize_version(v: &str) -> String {
    let no_epoch = v.split_once(':').map_or(v, |(_, rest)| rest);
    match no_epoch.rfind('-') {
        Some(i) => no_epoch[..i].to_string(),
        None => no_epoch.to_string(),
    }
}

/// Match installed packages to CVEs and record them as host-level vulns (port 0),
/// version-accurate from the installed versions.
fn assess_packages(
    store: &Store,
    scan_id: i64,
    asset_id: i64,
    inv: &pontus_core::SshInventory,
    explicit: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let kev = load_kev_cache();
    let mut cache: HashMap<(String, Option<String>), Vec<Vuln>> = HashMap::new();

    // Build the (product, version) work list. With an explicit list, assess exactly
    // those packages (by name); otherwise pick inventory packages whose name matches
    // a known network-service product, assessed under that canonical product name.
    let mut targets: Vec<(String, String)> = Vec::new(); // (product-to-query, version)
    match explicit {
        Some(list) => {
            for want in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                match inv.packages.iter().find(|p| p.name == want || p.name.starts_with(want)) {
                    Some(p) => targets.push((want.to_string(), normalize_version(&p.version))),
                    None => println!("       assess {want}: not installed"),
                }
            }
        }
        None => {
            for p in &inv.packages {
                if let Some(prod) = CRED_ASSESS_PRODUCTS.iter().find(|e| p.name == **e || p.name.starts_with(*e)) {
                    targets.push((prod.to_string(), normalize_version(&p.version)));
                }
            }
        }
    }
    if targets.is_empty() {
        println!("  no packages selected for CVE matching (try --assess-packages <names>)");
        return Ok(());
    }

    let mut total = 0usize;
    for (product, version) in targets {
        let vulns = cache.entry((product.clone(), Some(version.clone()))).or_insert_with(|| {
            match pontus_core::intel::assess(&product, Some(&version), &kev) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("note: vuln assessment for {product} failed: {e}");
                    Vec::new()
                }
            }
        });
        println!("       vulns: {product} {version} → {} CVE(s)", vulns.len());
        for v in vulns.iter() {
            store.record_vuln(scan_id, asset_id, 0, v)?; // port 0 = host-level
            total += 1;
        }
    }
    println!("  recorded {total} CVE finding(s) — see `pontus-cli risk`");
    Ok(())
}

fn print_tls_report(r: &pontus_core::TlsReport) {
    println!("\nprotocols:");
    for p in &r.protocols {
        let mark = if p.supported { "yes" } else { "no" };
        let cipher = p.cipher.as_deref().map(|c| format!("  {c}")).unwrap_or_default();
        let dep = if p.supported && p.version.is_deprecated() { "  [deprecated]" } else { "" };
        println!("  {:<8} {:<3}{}{}", p.version.label(), mark, cipher, dep);
    }
    if !r.weak_ciphers.is_empty() {
        println!("\nweak ciphers accepted: {}", r.weak_ciphers.join(", "));
    }
    if let Some(c) = &r.cert {
        println!("\ncertificate:");
        println!("  subject:     {}", c.subject);
        println!("  issuer:      {}", c.issuer);
        if !c.sans.is_empty() {
            println!("  SANs:        {}", c.sans.join(", "));
        }
        println!("  valid:       {} → {}", fmt_ts(c.not_before), fmt_ts(c.not_after));
        let key = c.key_bits.map_or_else(|| c.key_type.clone(), |b| format!("{} {b}", c.key_type));
        println!("  key:         {key}");
        println!("  signature:   {}", c.signature_algorithm);
        println!("  self-signed: {}", c.self_signed);
    }
    println!("\nfindings:");
    if r.findings.is_empty() {
        println!("  none — no weaknesses detected");
    } else {
        for f in &r.findings {
            println!("  - {}", f.describe());
        }
    }
}

/// Format a Unix timestamp as an ISO 8601 UTC date-time.
fn fmt_ts(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%SZ").to_string())
        .unwrap_or_else(|| ts.to_string())
}

fn run_netinfo() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = pontus_core::local_config();

    println!("interfaces:");
    for i in &cfg.interfaces {
        let mut flags = Vec::new();
        flags.push(if i.up { "up" } else { "down" });
        if i.loopback {
            flags.push("loopback");
        }
        println!("  {:<12} {:<18} [{}]", i.name, i.mac.as_deref().unwrap_or("-"), flags.join(", "));
        for a in &i.addrs {
            match &a.netmask {
                Some(mask) => println!("      {} /{}  mask {}", a.ip, a.prefix, mask),
                None => println!("      {} /{}", a.ip, a.prefix),
            }
        }
    }

    println!("\nlistening ports:");
    if cfg.listening.is_empty() {
        println!("  (none, or unavailable on this platform)");
    }
    for p in &cfg.listening {
        println!("  {:<5} {}:{}", p.proto, p.address, p.port);
    }
    Ok(())
}

fn run_http(args: HttpArgs) -> Result<(), Box<dyn std::error::Error>> {
    use std::net::ToSocketAddrs;

    let addr = (args.target.as_str(), args.port)
        .to_socket_addrs()?
        .next()
        .ok_or("could not resolve target")?;

    // Scope enforcement (F-007): refuse before any request. Defaults to the target.
    let scope_specs: Vec<String> =
        if args.scope.is_empty() { vec![addr.ip().to_string()] } else { args.scope.clone() };
    let scope = Scope::parse(&scope_specs)?;
    scope.ensure(addr.ip())?;

    let corpus = match &args.web_corpus {
        Some(path) => pontus_core::WebCorpus::load(path)?,
        None => pontus_core::WebCorpus::builtin(),
    };
    let scheme = if args.port == 443 { "https" } else { "http" };
    let url = format!("{scheme}://{}:{}/", args.target, args.port);
    println!("http: {url}  ({})", addr.ip());
    let fp = pontus_core::webtech::fingerprint(&url, &corpus, Duration::from_millis(args.timeout_ms))?;
    print_web_fingerprint(&fp);
    Ok(())
}

/// Compact a full TLS report into the storable observation summary (F-016).
fn tls_to_obs(r: &pontus_core::TlsReport) -> pontus_core::TlsObservation {
    pontus_core::TlsObservation {
        protocols: r.protocols.iter().filter(|p| p.supported).map(|p| p.version.label().to_string()).collect(),
        weak_ciphers: r.weak_ciphers.clone(),
        cert_subject: r.cert.as_ref().map(|c| c.subject.clone()),
        cert_not_after: r.cert.as_ref().map(|c| c.not_after),
        self_signed: r.cert.as_ref().is_some_and(|c| c.self_signed),
        findings: r.findings.iter().map(|f| f.describe()).collect(),
    }
}

fn tech_to_obs(t: &pontus_core::Tech) -> pontus_core::TechObservation {
    pontus_core::TechObservation {
        name: t.name.clone(),
        version: t.version.clone(),
        category: t.category.as_str().to_string(),
    }
}

fn print_web_fingerprint(fp: &pontus_core::WebFingerprint) {
    println!("status: {}", fp.status);
    if fp.techs.is_empty() {
        println!("\nno technologies identified");
        return;
    }
    println!("\ntechnologies:");
    for t in &fp.techs {
        let ver = t.version.as_deref().map(|v| format!(" {v}")).unwrap_or_default();
        println!("  {:<11} {}{}  ({})", t.category.as_str(), t.name, ver, t.evidence);
    }
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

fn join_ports(ports: &[pontus_core::PortRef]) -> String {
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
                    ..Default::default()
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

/// Render UDP results (open and open|filtered) for the console; closed omitted.
fn render_udp(results: &[udp::UdpResult]) -> String {
    results
        .iter()
        .filter(|r| r.state != UdpState::Closed)
        .map(|r| match &r.response {
            Some(b) if !b.is_empty() => format!("{}({})", r.port, truncate(b, 20)),
            _ => format!("{}({})", r.port, r.state.as_str()),
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

/// Parse a port spec into a sorted, de-duplicated list. Accepts single ports,
/// inclusive ranges, and `-` as shorthand for all of 1–65535, mixed freely:
/// `80,443,8000-8100`, `1-1024`, `-`. Port 0 is dropped (IMP-013).
fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let mut ports = std::collections::BTreeSet::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if part == "-" {
            ports.extend(1..=u16::MAX);
        } else if let Some((a, b)) = part.split_once('-') {
            let start: u16 = a.trim().parse().map_err(|_| format!("invalid port '{}'", a.trim()))?;
            let end: u16 = b.trim().parse().map_err(|_| format!("invalid port '{}'", b.trim()))?;
            if start > end {
                return Err(format!("invalid range '{part}' (start > end)"));
            }
            ports.extend(start..=end);
        } else {
            ports.insert(part.parse::<u16>().map_err(|_| format!("invalid port '{part}'"))?);
        }
    }
    ports.remove(&0); // port 0 is not a valid target
    if ports.is_empty() {
        return Err("no ports specified".to_string());
    }
    Ok(ports.into_iter().collect())
}

/// Resolve the TCP port list from `--ports` plus an optional `--top-ports N`
/// preset, unioned and de-duplicated (IMP-013).
fn resolve_ports(spec: &str, top: Option<u16>) -> Result<Vec<u16>, String> {
    let mut ports: std::collections::BTreeSet<u16> = parse_ports(spec)?.into_iter().collect();
    if let Some(n) = top {
        let n = (n as usize).min(TOP_PORTS.len());
        ports.extend(TOP_PORTS.iter().take(n).copied());
    }
    Ok(ports.into_iter().collect())
}

/// A curated, clean-room list of common TCP service ports, roughly by prevalence,
/// for the `--top-ports <N>` preset. Written from public well-known-port knowledge
/// (IANA / common service defaults), not from Nmap's frequency data (C-001).
const TOP_PORTS: &[u16] = &[
    80, 443, 22, 21, 25, 23, 53, 110, 143, 139, 445, 135, 3389, 3306, 8080, 1723, 111, 995, 993,
    5900, 1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001, 10000, 514, 5060, 179, 1026, 2000,
    8443, 8000, 32768, 554, 26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646, 5000, 5631,
    631, 49153, 8081, 2049, 88, 79, 5800, 106, 2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156,
    543, 544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009, 7070, 5190, 3000, 5432, 1900, 3986,
    13, 1029, 9, 6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37, 1000, 3001, 5001, 82,
    10010, 1030, 9090, 2107, 1024, 2103, 6004, 1801, 5050, 19, 8031, 1041, 255, 1048, 1049, 6379,
    27017, 9200, 11211, 32400,
];

/// Build the plugin host with every runner available in this build (F-020, D-003).
/// The Python runner is present only in a `--features python` build.
fn build_plugin_host() -> PluginHost {
    let mut host = PluginHost::new();
    host.register(Box::new(pontus_plugins::LuaRunner::new()));
    host.register(Box::new(pontus_plugins::WasmRunner::new()));
    #[cfg(feature = "python")]
    host.register(Box::new(pontus_plugins::PythonRunner::new()));
    host
}

/// Map a plugin file's extension to its language. `None` for unknown extensions.
fn plugin_language(path: &Path) -> Option<Language> {
    match path.extension().and_then(|e| e.to_str()) {
        Some("lua") => Some(Language::Lua),
        Some("wasm") | Some("wat") => Some(Language::Wasm),
        Some("py") => Some(Language::Python),
        _ => None,
    }
}

/// Load every recognised plugin file from `dir` (non-recursive). Unknown
/// extensions are skipped; a `.py` plugin in a non-`python` build is skipped with
/// a note. The plugin name is the file stem.
fn load_plugins(dir: &str) -> Vec<Plugin> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("note: --plugins {dir}: {e}");
            return Vec::new();
        }
    };
    let mut plugins = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(language) = plugin_language(&path) else { continue };
        if language == Language::Python && !cfg!(feature = "python") {
            eprintln!("note: skipping {} — Python plugins need a --features python build", path.display());
            continue;
        }
        let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("plugin").to_string();
        plugins.push(Plugin::from_path(name, language, path));
    }
    plugins.sort_by(|a, b| a.name.cmp(&b.name));
    plugins
}

/// Build a plugin `Target` from a scanned host's observation.
fn build_target(host: &DiscoveredHost, hostname: Option<&str>, ports: &[PortObservation]) -> pontus_plugins::Target {
    pontus_plugins::Target {
        ip: host.ip.to_string(),
        hostname: hostname.map(str::to_string),
        ports: ports
            .iter()
            .map(|p| pontus_plugins::TargetPort {
                port: p.port,
                proto: p.proto.clone(),
                service: p.service.clone(),
                version: p.version.clone(),
            })
            .collect(),
    }
}

/// Map a plugin finding onto the store's persisted shape, keyed to an asset.
fn to_stored(f: &pontus_plugins::Finding, asset_id: i64) -> StoredFinding {
    StoredFinding {
        asset_id,
        plugin: f.plugin.clone(),
        title: f.title.clone(),
        severity: f.severity.as_str().to_string(),
        description: f.description.clone(),
        metadata: f.metadata.clone(),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_ports_sorted_and_deduped() {
        assert_eq!(parse_ports("443,80,80").unwrap(), vec![80, 443]);
    }

    #[test]
    fn normalize_version_strips_epoch_and_revision() {
        assert_eq!(normalize_version("1:8.9p1-3ubuntu0.10"), "8.9p1"); // dpkg w/ epoch
        assert_eq!(normalize_version("9.3p1-9.fc39"), "9.3p1"); // rpm version-release
        assert_eq!(normalize_version("1.18.0-6ubuntu14.4"), "1.18.0"); // dpkg revision
        assert_eq!(normalize_version("1.2.3"), "1.2.3"); // bare upstream, unchanged
        assert_eq!(normalize_version("1.2.3-rc1-1"), "1.2.3-rc1"); // only the last '-' is the revision
        assert_eq!(normalize_version(""), ""); // empty (e.g. apk) stays empty
    }

    #[test]
    fn plugin_language_maps_known_extensions() {
        assert_eq!(plugin_language(Path::new("p.lua")), Some(Language::Lua));
        assert_eq!(plugin_language(Path::new("p.wasm")), Some(Language::Wasm));
        assert_eq!(plugin_language(Path::new("p.wat")), Some(Language::Wasm));
        assert_eq!(plugin_language(Path::new("p.py")), Some(Language::Python));
        assert_eq!(plugin_language(Path::new("README.md")), None);
        assert_eq!(plugin_language(Path::new("noext")), None);
    }

    #[test]
    fn parses_ranges_and_mixed_specs() {
        assert_eq!(parse_ports("1-5").unwrap(), vec![1, 2, 3, 4, 5]);
        assert_eq!(parse_ports("80,443,8000-8002").unwrap(), vec![80, 443, 8000, 8001, 8002]);
        // Overlapping range + single collapse.
        assert_eq!(parse_ports("20-22,21").unwrap(), vec![20, 21, 22]);
    }

    #[test]
    fn dash_means_all_ports() {
        let all = parse_ports("-").unwrap();
        assert_eq!(all.len(), 65535);
        assert_eq!(*all.first().unwrap(), 1);
        assert_eq!(*all.last().unwrap(), 65535);
    }

    #[test]
    fn port_zero_is_dropped_and_empty_is_an_error() {
        assert_eq!(parse_ports("0,22").unwrap(), vec![22]);
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("").is_err());
    }

    #[test]
    fn rejects_bad_ports_and_reversed_ranges() {
        assert!(parse_ports("nope").is_err());
        assert!(parse_ports("70000").is_err()); // > u16
        assert!(parse_ports("100-50").is_err());
    }

    #[test]
    fn top_ports_unions_with_explicit_ports() {
        let p = resolve_ports("32400", Some(5)).unwrap();
        // The five most common ports plus the explicit one, sorted/deduped.
        for common in &TOP_PORTS[..5] {
            assert!(p.contains(common), "missing top port {common}");
        }
        assert!(p.contains(&32400));
        // N beyond the list length is clamped, not an error.
        assert_eq!(resolve_ports("80", Some(9999)).unwrap().len(), {
            let mut s: std::collections::BTreeSet<u16> = TOP_PORTS.iter().copied().collect();
            s.insert(80);
            s.len()
        });
    }
}
