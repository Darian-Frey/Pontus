//! Host identity resolution (F-004, C-003).
//!
//! Given the signals seen for a host on one scan, find the durable asset they
//! belong to — or create one. The resolution order is fixed and load-bearing:
//!
//! ```text
//! MAC  →  host key / TLS cert fingerprint  →  hostname  →  IP
//! ```
//!
//! IP is the last resort and never the anchor when anything stronger is present.
//! This is what makes a host that changes address between scans (DHCP lease change,
//! cloud churn) resolve back to the *same* asset rather than spawning a duplicate.

use crate::error::{Error, Result};
use crate::model::{IdentityKind, IdentitySignals};
use rusqlite::{Connection, OptionalExtension, params};

/// Resolve `sig` to an asset id against `conn`, creating the asset if new and
/// otherwise merging the fresh signals into the existing row. `now` is an ISO 8601
/// timestamp used for `first_seen`/`last_seen`.
pub fn resolve(conn: &Connection, sig: &IdentitySignals, now: &str) -> Result<i64> {
    let ip = sig.ip.map(|i| i.to_string());
    if sig.mac.is_none() && sig.host_key.is_none() && sig.hostname.is_none() && ip.is_none() {
        return Err(Error::NoIdentitySignal);
    }

    // Look for an existing asset by the strongest signal first, stopping at the
    // first hit. A bare IP only matches an asset that is *itself* IP-anchored, so
    // a stronger-identified host reappearing on a recycled address is never
    // mistaken for the previous tenant of that address.
    let mut found = None;
    if let Some(v) = &sig.mac {
        found = lookup(conn, "mac", v)?;
    }
    if found.is_none() {
        if let Some(v) = &sig.host_key {
            found = lookup(conn, "host_key", v)?;
        }
    }
    if found.is_none() {
        if let Some(v) = &sig.hostname {
            found = lookup(conn, "hostname", v)?;
        }
    }
    if found.is_none() {
        if let Some(v) = &ip {
            found = conn
                .query_row(
                    "SELECT id FROM assets WHERE last_ip = ?1 AND identity_kind = 'ip'",
                    params![v],
                    |r| r.get(0),
                )
                .optional()?;
        }
    }

    match found {
        Some(id) => {
            merge(conn, id, sig, ip.as_deref(), now)?;
            Ok(id)
        }
        None => insert(conn, sig, ip.as_deref(), now),
    }
}

/// Find an asset by an exact match on one identity column. `col` is from a fixed
/// internal set, never user input.
fn lookup(conn: &Connection, col: &str, value: &str) -> Result<Option<i64>> {
    let sql = format!("SELECT id FROM assets WHERE {col} = ?1");
    Ok(conn
        .query_row(&sql, params![value], |r| r.get(0))
        .optional()?)
}

fn insert(conn: &Connection, sig: &IdentitySignals, ip: Option<&str>, now: &str) -> Result<i64> {
    let (kind, value) = strongest(sig.mac.as_deref(), sig.host_key.as_deref(), sig.hostname.as_deref(), ip)
        .expect("resolve() guarantees at least one signal");
    conn.execute(
        "INSERT INTO assets
            (identity_kind, identity_value, mac, host_key, hostname, last_ip, first_seen, last_seen)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)",
        params![kind.as_str(), value, sig.mac, sig.host_key, sig.hostname, ip, now],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Merge fresh signals into an existing asset: stronger fields fill blanks, the IP
/// is updated to wherever the host now lives, and the anchor is re-derived (so a
/// host first seen by hostname is promoted to MAC-anchored once its MAC appears).
fn merge(conn: &Connection, id: i64, sig: &IdentitySignals, ip: Option<&str>, now: &str) -> Result<()> {
    let (mac, host_key, hostname, last_ip): (Option<String>, Option<String>, Option<String>, Option<String>) =
        conn.query_row(
            "SELECT mac, host_key, hostname, last_ip FROM assets WHERE id = ?1",
            params![id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )?;

    // New signals win; absent ones keep the stored value. The IP always tracks the
    // latest sighting (this is the forced-IP-change path, F-004).
    let mac = sig.mac.clone().or(mac);
    let host_key = sig.host_key.clone().or(host_key);
    let hostname = sig.hostname.clone().or(hostname);
    let last_ip = ip.map(str::to_string).or(last_ip);

    let (kind, value) = strongest(
        mac.as_deref(),
        host_key.as_deref(),
        hostname.as_deref(),
        last_ip.as_deref(),
    )
    .expect("a stored asset always has at least one identity field");

    conn.execute(
        "UPDATE assets SET
            identity_kind = ?1, identity_value = ?2,
            mac = ?3, host_key = ?4, hostname = ?5, last_ip = ?6, last_seen = ?7
         WHERE id = ?8",
        params![kind.as_str(), value, mac, host_key, hostname, last_ip, now, id],
    )?;
    Ok(())
}

/// Pick the strongest available signal and its value, in priority order.
fn strongest<'a>(
    mac: Option<&'a str>,
    host_key: Option<&'a str>,
    hostname: Option<&'a str>,
    ip: Option<&'a str>,
) -> Option<(IdentityKind, &'a str)> {
    if let Some(v) = mac {
        Some((IdentityKind::Mac, v))
    } else if let Some(v) = host_key {
        Some((IdentityKind::HostKey, v))
    } else if let Some(v) = hostname {
        Some((IdentityKind::Hostname, v))
    } else {
        ip.map(|v| (IdentityKind::Ip, v))
    }
}
