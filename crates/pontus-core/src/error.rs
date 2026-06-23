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

    /// Identity resolution was handed no usable signal at all — not even an IP.
    /// See the resolution hierarchy in [`crate::identity`] (C-003, F-004).
    #[error("identity resolution needs at least one signal (MAC, host key, hostname or IP)")]
    NoIdentitySignal,
}

pub type Result<T> = std::result::Result<T, Error>;
