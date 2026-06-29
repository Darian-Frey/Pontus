//! The SQLite asset/observation store (F-003, D-002, D-007).
//!
//! Two first-class tables — durable `assets` and append-only `observations` —
//! plus a `scans` table that doubles as the audit log (F-007). Append-only is not
//! merely a convention here: triggers reject any `UPDATE` or `DELETE` on
//! `observations`, so the invariant holds even against direct SQL.

use crate::error::Result;
use crate::identity;
use crate::model::{IdentitySignals, ObservationState};
use chrono::Utc;
use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::path::Path;

const SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS assets (
    id             INTEGER PRIMARY KEY,
    identity_kind  TEXT NOT NULL,          -- 'mac' | 'host_key' | 'hostname' | 'ip'
    identity_value TEXT NOT NULL,
    mac            TEXT,
    host_key       TEXT,
    hostname       TEXT,
    last_ip        TEXT,
    first_seen     TEXT NOT NULL,
    last_seen      TEXT NOT NULL,
    UNIQUE (identity_kind, identity_value)
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    targets     TEXT NOT NULL,             -- requested target spec (audit)
    scope       TEXT NOT NULL,             -- declared scope (audit, F-007)
    operator    TEXT
);

-- Store-level settings (e.g. the designated baseline scan, F-014).
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS observations (
    id          INTEGER PRIMARY KEY,
    asset_id    INTEGER NOT NULL REFERENCES assets(id),
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    observed_at TEXT NOT NULL,
    ip          TEXT NOT NULL,
    state       TEXT NOT NULL,             -- JSON ObservationState
    UNIQUE (asset_id, scan_id, observed_at)
);

CREATE INDEX IF NOT EXISTS idx_obs_asset ON observations(asset_id);
CREATE INDEX IF NOT EXISTS idx_obs_scan  ON observations(scan_id);

-- Observations are append-only (D-007): reject mutation at the storage layer.
CREATE TRIGGER IF NOT EXISTS observations_no_update
    BEFORE UPDATE ON observations
    BEGIN SELECT RAISE(ABORT, 'observations are append-only'); END;

CREATE TRIGGER IF NOT EXISTS observations_no_delete
    BEFORE DELETE ON observations
    BEGIN SELECT RAISE(ABORT, 'observations are append-only'); END;

-- Topology edges from traceroute (F-009): src is one hop before dst on a path.
CREATE TABLE IF NOT EXISTS edges (
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    src     TEXT NOT NULL,
    dst     TEXT NOT NULL,
    UNIQUE (scan_id, src, dst)
);

-- Vulnerabilities matched to a host's service in a scan (F-015): CVE plus the
-- three triage signals (CVSS, EPSS, KEV). Scored in the intel layer, not here.
CREATE TABLE IF NOT EXISTS vulns (
    scan_id  INTEGER NOT NULL REFERENCES scans(id),
    asset_id INTEGER NOT NULL REFERENCES assets(id),
    port     INTEGER NOT NULL,
    cve_id   TEXT NOT NULL,
    cvss     REAL,
    epss     REAL,
    kev      INTEGER NOT NULL,
    version_matched INTEGER NOT NULL DEFAULT 1,
    UNIQUE (scan_id, asset_id, port, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_vulns_scan ON vulns(scan_id);

-- Plugin findings for a host in a scan (F-020). Produced by the plugin host
-- (pontus-plugins) and persisted here; the store does not depend on the plugin
-- runtime — the CLI maps a plugin Finding onto these columns. metadata is a JSON
-- object of string keys/values.
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    asset_id    INTEGER NOT NULL REFERENCES assets(id),
    plugin      TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    metadata    TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"#;

/// A scan's audit record, for listing and diff headers.
#[derive(Debug, Clone, Serialize)]
pub struct ScanRef {
    pub id: i64,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub targets: String,
}

/// A directed topology edge: `from` is one hop before `to` on a traced path (F-009).
#[derive(Debug, Clone, Serialize)]
pub struct Edge {
    pub from: String,
    pub to: String,
}

/// A scored vulnerability within a host's risk view (F-015).
#[derive(Debug, Clone, Serialize)]
pub struct RankedVuln {
    pub cve_id: String,
    pub cvss: Option<f32>,
    pub epss: Option<f32>,
    pub kev: bool,
    pub band: String,
    pub score: f32,
    /// `false` for a product-wide (version-less) match — lower confidence (IMP-003).
    pub version_matched: bool,
}

/// A host ranked by vulnerability risk, with its vulnerabilities worst-first (F-015).
#[derive(Debug, Clone, Serialize)]
pub struct HostRisk {
    pub asset_id: i64,
    pub identity_kind: String,
    pub identity_value: String,
    pub ip: Option<String>,
    pub risk: f32,
    pub vulns: Vec<RankedVuln>,
}

/// A stored vulnerability joined to its asset identity, for the risk view (F-015).
#[derive(Debug, Clone, Serialize)]
pub struct AssetVuln {
    pub asset_id: i64,
    pub identity_kind: String,
    pub identity_value: String,
    pub ip: Option<String>,
    pub port: u16,
    pub cve_id: String,
    pub cvss: Option<f32>,
    pub epss: Option<f32>,
    pub kev: bool,
    pub version_matched: bool,
}

/// A plugin finding persisted against an asset (F-020). On read it carries the
/// asset's identity for display; on write `identity`/`ip` are ignored (the row is
/// keyed by `asset_id`). The store layer is independent of the plugin runtime —
/// the CLI maps a `pontus_plugins::Finding` onto this.
#[derive(Debug, Clone, Default, Serialize)]
pub struct StoredFinding {
    pub asset_id: i64,
    #[serde(default)]
    pub identity: String,
    #[serde(default)]
    pub ip: Option<String>,
    pub plugin: String,
    pub title: String,
    pub severity: String,
    pub description: String,
    pub metadata: std::collections::BTreeMap<String, String>,
}

/// One observation in an asset's history, for the GUI detail pane.
#[derive(Debug, Clone, Serialize)]
pub struct AssetObservation {
    pub scan_id: i64,
    pub observed_at: String,
    pub ip: String,
    pub state: ObservationState,
}

/// One host's observation within a scan, joined to its asset identity. The unit a
/// diff compares (F-014).
#[derive(Debug, Clone, Serialize)]
pub struct HostObservation {
    pub asset_id: i64,
    pub identity_kind: String,
    pub identity_value: String,
    pub ip: String,
    pub state: ObservationState,
}

/// A row of the asset table, flattened for display (the CLI `assets` command and
/// the GUI inventory).
#[derive(Debug, Clone, Serialize)]
pub struct AssetSummary {
    pub id: i64,
    pub identity_kind: String,
    pub identity_value: String,
    pub hostname: Option<String>,
    pub last_ip: Option<String>,
    pub last_seen: String,
    pub observations: i64,
    /// Most recent observation's OS guess, if any (F-013, surfaced in the GUI).
    pub os: Option<String>,
    /// The asset's MAC, if one has ever been learned (None for IP-only hosts).
    pub mac: Option<String>,
}

/// Handle to the Pontus store.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open (creating if absent) a store at `path` and apply the schema.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;
        Self::from_conn(conn)
    }

    /// An ephemeral in-memory store — used by the test suite.
    pub fn open_in_memory() -> Result<Self> {
        Self::from_conn(Connection::open_in_memory()?)
    }

    fn from_conn(conn: Connection) -> Result<Self> {
        conn.execute_batch(SCHEMA)?;
        // Idempotent migration: add columns introduced after a store may have been
        // created. SQLite has no ADD COLUMN IF NOT EXISTS, so a duplicate-column
        // error just means it is already present (IMP-003).
        let _ = conn.execute("ALTER TABLE vulns ADD COLUMN version_matched INTEGER NOT NULL DEFAULT 1", []);
        Ok(Self { conn })
    }

    /// Open a scan and write its audit record (targets, scope, operator, time).
    /// Returns the scan id that subsequent observations are tagged with.
    pub fn begin_scan(&self, targets: &str, scope: &str, operator: Option<&str>) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO scans (started_at, targets, scope, operator) VALUES (?1, ?2, ?3, ?4)",
            params![now, targets, scope, operator],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Stamp a scan as finished.
    pub fn finish_scan(&self, scan_id: i64) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "UPDATE scans SET finished_at = ?1 WHERE id = ?2",
            params![now, scan_id],
        )?;
        Ok(())
    }

    /// Resolve `sig` to an asset and append one observation against it for `scan_id`.
    /// Returns the resolved asset id. This is the single write path a scan uses; it
    /// never mutates a prior observation (D-007).
    pub fn record(&self, sig: &IdentitySignals, scan_id: i64, state: &ObservationState) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        let asset_id = identity::resolve(&self.conn, sig, &now)?;
        let ip = sig.ip.map(|i| i.to_string()).unwrap_or_default();
        let json = serde_json::to_string(state)?;
        self.conn.execute(
            "INSERT INTO observations (asset_id, scan_id, observed_at, ip, state)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![asset_id, scan_id, now, ip, json],
        )?;
        Ok(asset_id)
    }

    pub fn asset_count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM assets", [], |r| r.get(0))?)
    }

    pub fn observation_count(&self) -> Result<i64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM observations", [], |r| r.get(0))?)
    }

    /// All assets with their observation counts, newest sighting first.
    pub fn list_assets(&self) -> Result<Vec<AssetSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT a.id, a.identity_kind, a.identity_value, a.hostname, a.last_ip, a.last_seen,
                    (SELECT COUNT(*) FROM observations o WHERE o.asset_id = a.id),
                    (SELECT json_extract(o.state, '$.os_guess') FROM observations o
                     WHERE o.asset_id = a.id ORDER BY o.observed_at DESC, o.id DESC LIMIT 1),
                    a.mac
             FROM assets a
             ORDER BY a.last_seen DESC, a.id ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(AssetSummary {
                id: r.get(0)?,
                identity_kind: r.get(1)?,
                identity_value: r.get(2)?,
                hostname: r.get(3)?,
                last_ip: r.get(4)?,
                last_seen: r.get(5)?,
                observations: r.get(6)?,
                os: r.get(7)?,
                mac: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// The most recent scans, newest first (for picking the two to diff).
    pub fn recent_scans(&self, limit: i64) -> Result<Vec<ScanRef>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, started_at, finished_at, targets FROM scans ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |r| {
            Ok(ScanRef {
                id: r.get(0)?,
                started_at: r.get(1)?,
                finished_at: r.get(2)?,
                targets: r.get(3)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// A single scan's audit record, if it exists.
    pub fn scan(&self, id: i64) -> Result<Option<ScanRef>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, started_at, finished_at, targets FROM scans WHERE id = ?1",
                [id],
                |r| {
                    Ok(ScanRef {
                        id: r.get(0)?,
                        started_at: r.get(1)?,
                        finished_at: r.get(2)?,
                        targets: r.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    /// Record a topology edge for a scan (idempotent per scan, F-009).
    pub fn record_edge(&self, scan_id: i64, from: &str, to: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO edges (scan_id, src, dst) VALUES (?1, ?2, ?3)",
            params![scan_id, from, to],
        )?;
        Ok(())
    }

    /// Record a vulnerability matched to a host's service in a scan (F-015).
    pub fn record_vuln(
        &self,
        scan_id: i64,
        asset_id: i64,
        port: u16,
        vuln: &crate::intel::Vuln,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO vulns
                (scan_id, asset_id, port, cve_id, cvss, epss, kev, version_matched)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                scan_id,
                asset_id,
                port,
                vuln.cve_id,
                vuln.cvss,
                vuln.epss,
                vuln.kev as i64,
                vuln.version_matched as i64
            ],
        )?;
        Ok(())
    }

    /// All vulnerabilities recorded by a scan, joined to their asset identity.
    pub fn vulns_for_scan(&self, scan_id: i64) -> Result<Vec<AssetVuln>> {
        let mut stmt = self.conn.prepare(
            "SELECT v.asset_id, a.identity_kind, a.identity_value, a.last_ip,
                    v.port, v.cve_id, v.cvss, v.epss, v.kev, v.version_matched
             FROM vulns v JOIN assets a ON a.id = v.asset_id
             WHERE v.scan_id = ?1",
        )?;
        let rows = stmt.query_map([scan_id], |r| {
            Ok(AssetVuln {
                asset_id: r.get(0)?,
                identity_kind: r.get(1)?,
                identity_value: r.get(2)?,
                ip: r.get(3)?,
                port: r.get(4)?,
                cve_id: r.get(5)?,
                cvss: r.get(6)?,
                epss: r.get(7)?,
                kev: r.get::<_, i64>(8)? != 0,
                version_matched: r.get::<_, i64>(9)? != 0,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Record a plugin finding for a host in a scan (F-020). `metadata` is stored
    /// as a JSON object. The store deliberately knows nothing about the plugin
    /// runtime — the caller maps a plugin `Finding` onto these fields.
    pub fn record_finding(&self, scan_id: i64, finding: &StoredFinding) -> Result<()> {
        let metadata = serde_json::to_string(&finding.metadata).unwrap_or_else(|_| "{}".to_string());
        self.conn.execute(
            "INSERT INTO findings
                (scan_id, asset_id, plugin, title, severity, description, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                scan_id,
                finding.asset_id,
                finding.plugin,
                finding.title,
                finding.severity,
                finding.description,
                metadata,
            ],
        )?;
        Ok(())
    }

    /// All plugin findings recorded by a scan, joined to their asset identity.
    pub fn findings_for_scan(&self, scan_id: i64) -> Result<Vec<StoredFinding>> {
        let mut stmt = self.conn.prepare(
            "SELECT f.asset_id, a.identity_value, a.last_ip,
                    f.plugin, f.title, f.severity, f.description, f.metadata
             FROM findings f JOIN assets a ON a.id = f.asset_id
             WHERE f.scan_id = ?1
             ORDER BY f.plugin, f.id",
        )?;
        let rows = stmt.query_map([scan_id], |r| {
            let metadata: String = r.get(7)?;
            Ok(StoredFinding {
                asset_id: r.get(0)?,
                identity: r.get(1)?,
                ip: r.get(2)?,
                plugin: r.get(3)?,
                title: r.get(4)?,
                severity: r.get(5)?,
                description: r.get(6)?,
                metadata: serde_json::from_str(&metadata).unwrap_or_default(),
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Hosts ranked by the C-002 exploitation-weighted risk model (F-015).
    ///
    /// Each host's vulnerabilities are scored ([`crate::intel::risk_score`]) and
    /// sorted worst-first; the host's own risk is its worst vulnerability, and the
    /// hosts are returned worst-first. This is the single scoring path shared by
    /// the CLI `risk` command and the FFI/GUI risk view.
    pub fn risk_ranked(&self, scan_id: i64) -> Result<Vec<HostRisk>> {
        use crate::intel::{Vuln, band, risk_score};
        let mut by_asset: std::collections::HashMap<i64, HostRisk> = std::collections::HashMap::new();
        for av in self.vulns_for_scan(scan_id)? {
            let v = Vuln {
                cve_id: av.cve_id.clone(),
                cvss: av.cvss,
                epss: av.epss,
                kev: av.kev,
                version_matched: av.version_matched,
            };
            let ranked = RankedVuln {
                band: band(&v).as_str().to_string(),
                score: risk_score(&v),
                cve_id: av.cve_id,
                cvss: av.cvss,
                epss: av.epss,
                kev: av.kev,
                version_matched: av.version_matched,
            };
            by_asset
                .entry(av.asset_id)
                .or_insert_with(|| HostRisk {
                    asset_id: av.asset_id,
                    identity_kind: av.identity_kind,
                    identity_value: av.identity_value,
                    ip: av.ip,
                    risk: 0.0,
                    vulns: Vec::new(),
                })
                .vulns
                .push(ranked);
        }
        let mut hosts: Vec<HostRisk> = by_asset
            .into_values()
            .map(|mut h| {
                // The same CVE can be recorded on several ports (e.g. a web server
                // on 80 and 443); the triage view is CVE-centric, so collapse to
                // one entry per CVE — you fix the CVE once, not per port.
                let mut seen = std::collections::HashSet::new();
                h.vulns.retain(|v| seen.insert(v.cve_id.clone()));
                h.vulns.sort_by(|a, b| b.score.total_cmp(&a.score));
                h.risk = h.vulns.first().map_or(0.0, |v| v.score);
                h
            })
            .collect();
        hosts.sort_by(|a, b| b.risk.total_cmp(&a.risk));
        Ok(hosts)
    }

    /// The topology edges recorded by a scan.
    pub fn edges_for_scan(&self, scan_id: i64) -> Result<Vec<Edge>> {
        let mut stmt = self.conn.prepare("SELECT src, dst FROM edges WHERE scan_id = ?1")?;
        let rows = stmt.query_map([scan_id], |r| Ok(Edge { from: r.get(0)?, to: r.get(1)? }))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Designate `scan_id` as the baseline this store diffs against (F-014).
    pub fn set_baseline(&self, scan_id: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES ('baseline', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![scan_id.to_string()],
        )?;
        Ok(())
    }

    /// The designated baseline scan id, if one has been set.
    pub fn baseline(&self) -> Result<Option<i64>> {
        let value: Option<String> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = 'baseline'", [], |r| r.get(0))
            .optional()?;
        Ok(value.and_then(|v| v.parse().ok()))
    }

    /// Every host observation recorded by one scan, joined to its asset identity.
    pub fn observations_for_scan(&self, scan_id: i64) -> Result<Vec<HostObservation>> {
        let mut stmt = self.conn.prepare(
            "SELECT o.asset_id, a.identity_kind, a.identity_value, o.ip, o.state
             FROM observations o JOIN assets a ON a.id = o.asset_id
             WHERE o.scan_id = ?1
             ORDER BY o.asset_id",
        )?;
        let rows = stmt.query_map([scan_id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (asset_id, identity_kind, identity_value, ip, state_json) = row?;
            let state: ObservationState = serde_json::from_str(&state_json)?;
            out.push(HostObservation { asset_id, identity_kind, identity_value, ip, state });
        }
        Ok(out)
    }

    /// One asset's observation history, newest first (the GUI detail pane).
    pub fn observations_for_asset(&self, asset_id: i64) -> Result<Vec<AssetObservation>> {
        let mut stmt = self.conn.prepare(
            "SELECT scan_id, observed_at, ip, state
             FROM observations
             WHERE asset_id = ?1
             ORDER BY observed_at DESC",
        )?;
        let rows = stmt.query_map([asset_id], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (scan_id, observed_at, ip, state_json) = row?;
            let state: ObservationState = serde_json::from_str(&state_json)?;
            out.push(AssetObservation { scan_id, observed_at, ip, state });
        }
        Ok(out)
    }

    /// Borrow the underlying connection (tests and future query helpers).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}
