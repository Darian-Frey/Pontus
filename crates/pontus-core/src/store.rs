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
"#;

/// A scan's audit record, for listing and diff headers.
#[derive(Debug, Clone, Serialize)]
pub struct ScanRef {
    pub id: i64,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub targets: String,
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
#[derive(Debug, Clone)]
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
                    (SELECT COUNT(*) FROM observations o WHERE o.asset_id = a.id)
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
