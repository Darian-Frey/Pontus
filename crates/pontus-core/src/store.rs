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
use rusqlite::{Connection, params};
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

/// A row of the asset table, flattened for display (the CLI `assets` command).
#[derive(Debug, Clone)]
pub struct AssetSummary {
    pub id: i64,
    pub identity_kind: String,
    pub identity_value: String,
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
            "SELECT a.id, a.identity_kind, a.identity_value, a.last_ip, a.last_seen,
                    (SELECT COUNT(*) FROM observations o WHERE o.asset_id = a.id)
             FROM assets a
             ORDER BY a.last_seen DESC, a.id ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(AssetSummary {
                id: r.get(0)?,
                identity_kind: r.get(1)?,
                identity_value: r.get(2)?,
                last_ip: r.get(3)?,
                last_seen: r.get(4)?,
                observations: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Borrow the underlying connection (tests and future query helpers).
    pub fn conn(&self) -> &Connection {
        &self.conn
    }
}
