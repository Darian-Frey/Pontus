//! Crate-wide error type.

use thiserror::Error;

/// Anything that can go wrong inside `pontus-core`.
#[derive(Debug, Error)]
pub enum Error {
    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error(transparent)]
    Scope(#[from] crate::scope::ScopeError),

    #[error("serialisation error: {0}")]
    Json(#[from] serde_json::Error),

    /// A file read failed — e.g. loading an OS fingerprint corpus (F-013).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A vulnerability-feed fetch failed (NVD/EPSS/KEV, F-015).
    #[error("intelligence feed error: {0}")]
    Feed(String),

    /// Identity resolution was handed no usable signal at all — not even an IP.
    /// See the resolution hierarchy in [`crate::identity`] (C-003, F-004).
    #[error("identity resolution needs at least one signal (MAC, host key, hostname or IP)")]
    NoIdentitySignal,
}

pub type Result<T> = std::result::Result<T, Error>;
