//! `pontus-api` — a small REST API over the headless core (F-024).
//!
//! Read endpoints reopen the store per request (SQLite handles concurrent readers,
//! so no shared connection/lock is needed); launching a scan shells out to the
//! capability-granted `pontus-cli` (D-008), so the API itself holds no raw
//! privilege. Binds to localhost by default; if `PONTUS_API_TOKEN` is set, every
//! request must carry `Authorization: Bearer <token>` — required before exposing
//! the API beyond loopback, since it can launch scans.

use clap::Parser;
use pontus_core::Store;
use serde::Deserialize;
use std::collections::HashMap;
use std::process::{Command, ExitCode};
use std::sync::Arc;
use std::thread;
use tiny_http::{Header, Method, Response, Server};

#[derive(Parser)]
#[command(name = "pontus-api", about = "REST API over pontus-core (F-024)")]
struct Cli {
    /// Store path to read from / scan into.
    #[arg(long, default_value = "pontus.db")]
    db: String,
    /// Address to bind. Keep it on loopback unless a token is set.
    #[arg(long, default_value = "127.0.0.1:8787")]
    bind: String,
    /// Path to the (capability-granted) pontus-cli, used to launch scans.
    #[arg(long, default_value = "pontus-cli")]
    cli: String,
    /// Worker threads serving requests.
    #[arg(long, default_value_t = 4)]
    threads: usize,
}

struct Config {
    db: String,
    cli: String,
    token: Option<String>,
}

/// A rendered response: status, content type, body.
struct Reply {
    status: u16,
    content_type: &'static str,
    body: String,
}

fn json(status: u16, body: String) -> Reply {
    Reply { status, content_type: "application/json", body }
}

fn error(status: u16, message: &str) -> Reply {
    json(status, format!("{{\"error\":{}}}", json_string(message)))
}

/// Minimal JSON string escaping for our own short messages.
fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let token = std::env::var("PONTUS_API_TOKEN").ok().filter(|t| !t.is_empty());
    let cfg = Arc::new(Config { db: cli.db, cli: cli.cli, token });

    let server = match Server::http(&cli.bind) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("error: could not bind {}: {e}", cli.bind);
            return ExitCode::FAILURE;
        }
    };
    println!(
        "pontus-api listening on http://{} (auth: {})",
        cli.bind,
        if cfg.token.is_some() { "token required" } else { "none — loopback only" }
    );

    let mut handles = Vec::new();
    for _ in 0..cli.threads.max(1) {
        let server = Arc::clone(&server);
        let cfg = Arc::clone(&cfg);
        handles.push(thread::spawn(move || {
            for mut req in server.incoming_requests() {
                let reply = handle(&mut req, &cfg);
                let resp = Response::from_string(reply.body)
                    .with_status_code(reply.status)
                    .with_header(
                        Header::from_bytes(&b"Content-Type"[..], reply.content_type.as_bytes())
                            .expect("valid header"),
                    );
                let _ = req.respond(resp);
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    ExitCode::SUCCESS
}

/// Authenticate, then route one request to a [`Reply`].
fn handle(req: &mut tiny_http::Request, cfg: &Config) -> Reply {
    // Snapshot request metadata before consuming the body.
    let method = req.method().clone();
    let url = req.url().to_string();
    let authorized = match &cfg.token {
        None => true,
        Some(tok) => req
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .map(|h| h.value.as_str())
            .and_then(|v| v.strip_prefix("Bearer "))
            .is_some_and(|t| t == tok),
    };
    if !authorized {
        return error(401, "missing or invalid bearer token");
    }

    let mut body = String::new();
    if method == Method::Post {
        let _ = req.as_reader().read_to_string(&mut body);
    }

    let (path, query) = url.split_once('?').unwrap_or((url.as_str(), ""));
    let segs: Vec<&str> = path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    let q = parse_query(query);

    route(&method, &segs, &q, &body, cfg)
}

fn route(method: &Method, segs: &[&str], q: &HashMap<String, String>, body: &str, cfg: &Config) -> Reply {
    match (method, segs) {
        (Method::Get, []) | (Method::Get, ["health"]) => json(
            200,
            format!("{{\"status\":\"ok\",\"tool\":\"pontus\",\"version\":\"{}\"}}", env!("CARGO_PKG_VERSION")),
        ),
        (Method::Get, ["assets"]) => with_store(cfg, |s| Ok(serde_json::to_string(&s.list_assets()?)?)),
        (Method::Get, ["scans"]) => with_store(cfg, |s| Ok(serde_json::to_string(&s.recent_scans(100)?)?)),
        (Method::Post, ["scans"]) => launch_scan(body, cfg),
        (Method::Get, ["scans", id, "observations"]) => scan_sub(cfg, id, |s, sid| {
            Ok(serde_json::to_string(&s.observations_for_scan(sid)?)?)
        }),
        (Method::Get, ["scans", id, "risk"]) => scan_sub(cfg, id, |s, sid| {
            Ok(serde_json::to_string(&s.risk_ranked(sid)?)?)
        }),
        (Method::Get, ["scans", id, "findings"]) => scan_sub(cfg, id, |s, sid| {
            Ok(serde_json::to_string(&s.findings_for_scan(sid)?)?)
        }),
        (Method::Get, ["scans", id, "export"]) => export(cfg, id, q.get("format").map(String::as_str).unwrap_or("json")),
        _ => error(404, "not found"),
    }
}

/// Open the store and run a read closure, mapping errors to 500.
fn with_store<F>(cfg: &Config, f: F) -> Reply
where
    F: FnOnce(&Store) -> Result<String, Box<dyn std::error::Error>>,
{
    match Store::open(&cfg.db).map_err(Into::into).and_then(|s| f(&s)) {
        Ok(body) => json(200, body),
        Err(e) => error(500, &e.to_string()),
    }
}

/// Like [`with_store`] but parses a scan id from the path first.
fn scan_sub<F>(cfg: &Config, id: &str, f: F) -> Reply
where
    F: FnOnce(&Store, i64) -> Result<String, Box<dyn std::error::Error>>,
{
    let Ok(sid) = id.parse::<i64>() else {
        return error(400, "scan id must be an integer");
    };
    with_store(cfg, |s| f(s, sid))
}

/// Export a scan in a report format (F-023 over HTTP).
fn export(cfg: &Config, id: &str, format: &str) -> Reply {
    let Ok(sid) = id.parse::<i64>() else {
        return error(400, "scan id must be an integer");
    };
    let content_type = match format {
        "html" => "text/html",
        "csv" => "text/csv",
        "json" | "sarif" => "application/json",
        _ => return error(400, "format must be html, json, sarif or csv"),
    };
    let store = match Store::open(&cfg.db) {
        Ok(s) => s,
        Err(e) => return error(500, &e.to_string()),
    };
    let report = match pontus_core::export::report(&store, sid) {
        Ok(r) => r,
        Err(e) => return error(404, &e.to_string()),
    };
    let body = match format {
        "html" => pontus_core::export::to_html(&report),
        "csv" => pontus_core::export::to_csv(&report),
        "sarif" => pontus_core::export::to_sarif(&report),
        _ => pontus_core::export::to_json(&report),
    };
    Reply { status: 200, content_type, body }
}

/// A scan launch request body.
#[derive(Debug, Deserialize)]
struct ScanRequest {
    targets: String,
    scope: OneOrMany,
    ports: Option<String>,
    top_ports: Option<u16>,
    udp_ports: Option<String>,
    #[serde(default)]
    assess_vulns: bool,
    #[serde(default)]
    inspect: bool,
    plugins: Option<String>,
    operator: Option<String>,
}

/// A field that may be a single string or a list of strings (e.g. `scope`).
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

/// Build the `pontus-cli scan` argument vector from a request (pure/testable).
fn scan_args(req: &ScanRequest, scope: &[String], db: &str) -> Vec<String> {
    let mut args = vec!["scan".to_string(), req.targets.clone(), "--db".to_string(), db.to_string()];
    for s in scope {
        args.push("--scope".to_string());
        args.push(s.clone());
    }
    if let Some(p) = &req.ports {
        args.push("--ports".to_string());
        args.push(p.clone());
    }
    if let Some(n) = req.top_ports {
        args.push("--top-ports".to_string());
        args.push(n.to_string());
    }
    if let Some(u) = &req.udp_ports {
        args.push("--udp-ports".to_string());
        args.push(u.clone());
    }
    if let Some(p) = &req.plugins {
        args.push("--plugins".to_string());
        args.push(p.clone());
    }
    if let Some(op) = &req.operator {
        args.push("--operator".to_string());
        args.push(op.clone());
    }
    if req.assess_vulns {
        args.push("--assess-vulns".to_string());
    }
    if req.inspect {
        args.push("--inspect".to_string());
    }
    args
}

/// Launch a scan by shelling out to pontus-cli (synchronous), returning the new
/// scan's id. Scope is mandatory (F-007); the CLI enforces it before any packet.
fn launch_scan(body: &str, cfg: &Config) -> Reply {
    let req: ScanRequest = match serde_json::from_str(body) {
        Ok(r) => r,
        Err(e) => return error(400, &format!("invalid JSON body: {e}")),
    };
    let scope = req.scope_vec();
    if req.targets.trim().is_empty() || scope.is_empty() {
        return error(400, "`targets` and `scope` are required");
    }
    let args = scan_args(&req, &scope, &cfg.db);
    let status = Command::new(&cfg.cli).args(&args).status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => return error(500, &format!("scan exited with {s}")),
        Err(e) => return error(500, &format!("could not launch {:?}: {e}", cfg.cli)),
    }
    // The new scan is the most recent one in the store.
    match Store::open(&cfg.db).and_then(|s| s.recent_scans(1)) {
        Ok(scans) => match scans.first() {
            Some(scan) => json(201, serde_json::to_string(scan).unwrap_or_default()),
            None => error(500, "scan completed but no scan row was found"),
        },
        Err(e) => error(500, &e.to_string()),
    }
}

impl ScanRequest {
    fn scope_vec(&self) -> Vec<String> {
        match &self.scope {
            OneOrMany::One(s) => vec![s.clone()],
            OneOrMany::Many(v) => v.clone(),
        }
    }
}

/// Parse a URL query string into a map (percent-decoding is not needed for our
/// simple `format=` values).
fn parse_query(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(scope: OneOrMany) -> ScanRequest {
        ScanRequest {
            targets: "192.168.1.0/24".into(),
            scope,
            ports: Some("22,80".into()),
            top_ports: Some(100),
            udp_ports: None,
            assess_vulns: true,
            inspect: false,
            plugins: None,
            operator: Some("api".into()),
        }
    }

    #[test]
    fn scan_args_maps_fields_to_flags() {
        let r = req(OneOrMany::Many(vec!["10.0.0.0/24".into(), "10.0.1.0/24".into()]));
        let args = scan_args(&r, &r.scope_vec(), "p.db");
        assert_eq!(&args[0..4], &["scan", "192.168.1.0/24", "--db", "p.db"]);
        assert_eq!(args.iter().filter(|a| *a == "--scope").count(), 2);
        assert!(args.windows(2).any(|w| w == ["--ports", "22,80"]));
        assert!(args.windows(2).any(|w| w == ["--top-ports", "100"]));
        assert!(args.iter().any(|a| a == "--assess-vulns"));
        assert!(!args.iter().any(|a| a == "--inspect"));
    }

    #[test]
    fn scope_accepts_a_string_or_a_list() {
        let one: ScanRequest = serde_json::from_str(
            r#"{"targets":"10.0.0.1","scope":"10.0.0.1"}"#,
        )
        .unwrap();
        assert_eq!(one.scope_vec(), vec!["10.0.0.1".to_string()]);
        let many: ScanRequest =
            serde_json::from_str(r#"{"targets":"x","scope":["a","b"]}"#).unwrap();
        assert_eq!(many.scope_vec(), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn query_parsing() {
        let q = parse_query("format=html&x=1");
        assert_eq!(q.get("format").map(String::as_str), Some("html"));
        assert!(parse_query("").is_empty());
    }
}
