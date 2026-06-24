//! `pontus-ffi` — the C-ABI shim over `pontus-core` (D-001).
//!
//! A deliberately narrow surface: the GUI opens a store handle and pulls read
//! views (inventory, an asset's history, scan list, a diff) as JSON strings, which
//! it parses on its side. JSON keeps the ABI tiny and stable — no C structs to
//! keep in lockstep — at the cost of a serialise/parse hop, which is negligible for
//! a desktop inventory view.
//!
//! ## Ownership contract (the caller must honour this)
//! - Every `*mut c_char` returned here is heap-allocated by Rust; free it with
//!   [`pontus_string_free`], never with libc `free`.
//! - The handle from [`pontus_open`] must be released with [`pontus_close`].
//! - A null return means "failed" (bad path, bad UTF-8, DB error, etc.).
//!
//! All functions are null-safe: passing null returns null / does nothing.

use pontus_core::{Store, diff_observations};
use std::ffi::{CStr, CString, c_char};
use std::ptr;

/// Opaque handle wrapping an open store. The GUI only ever holds a pointer.
pub struct PontusHandle {
    store: Store,
}

/// Open (creating if absent) a store at `db_path`. Returns null on failure.
///
/// # Safety
/// `db_path` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pontus_open(db_path: *const c_char) -> *mut PontusHandle {
    if db_path.is_null() {
        return ptr::null_mut();
    }
    let path = match unsafe { CStr::from_ptr(db_path) }.to_str() {
        Ok(p) => p,
        Err(_) => return ptr::null_mut(),
    };
    match Store::open(path) {
        Ok(store) => Box::into_raw(Box::new(PontusHandle { store })),
        Err(_) => ptr::null_mut(),
    }
}

/// Close a handle from [`pontus_open`].
///
/// # Safety
/// `handle` must come from [`pontus_open`] and not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pontus_close(handle: *mut PontusHandle) {
    if !handle.is_null() {
        drop(unsafe { Box::from_raw(handle) });
    }
}

/// The shim/core version string. Caller frees with [`pontus_string_free`].
#[unsafe(no_mangle)]
pub extern "C" fn pontus_version() -> *mut c_char {
    into_c_string(Some(env!("CARGO_PKG_VERSION").to_string()))
}

/// JSON array of all assets (id, identity, hostname, last IP, observation count).
///
/// # Safety
/// `handle` must be a valid handle from [`pontus_open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pontus_assets_json(handle: *mut PontusHandle) -> *mut c_char {
    with_handle(handle, |h| serde_json::to_string(&h.store.list_assets().ok()?).ok())
}

/// JSON array of the most recent `limit` scans (audit records).
///
/// # Safety
/// `handle` must be a valid handle from [`pontus_open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pontus_scans_json(handle: *mut PontusHandle, limit: i64) -> *mut c_char {
    with_handle(handle, |h| {
        serde_json::to_string(&h.store.recent_scans(limit.max(0)).ok()?).ok()
    })
}

/// JSON array of one asset's observation history (newest first).
///
/// # Safety
/// `handle` must be a valid handle from [`pontus_open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pontus_asset_history_json(
    handle: *mut PontusHandle,
    asset_id: i64,
) -> *mut c_char {
    with_handle(handle, |h| {
        serde_json::to_string(&h.store.observations_for_asset(asset_id).ok()?).ok()
    })
}

/// JSON array of per-host changes between two scans (F-014).
///
/// # Safety
/// `handle` must be a valid handle from [`pontus_open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pontus_diff_json(
    handle: *mut PontusHandle,
    from_scan: i64,
    to_scan: i64,
) -> *mut c_char {
    with_handle(handle, |h| {
        let from = h.store.observations_for_scan(from_scan).ok()?;
        let to = h.store.observations_for_scan(to_scan).ok()?;
        serde_json::to_string(&diff_observations(&from, &to)).ok()
    })
}

/// Designate `scan_id` as the baseline this store diffs against (F-014). Returns
/// true on success. This is a metadata write to the GUI's own store — distinct
/// from scanning, which the GUI does by shelling out to the CLI (D-008).
///
/// # Safety
/// `handle` must be a valid handle from [`pontus_open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pontus_set_baseline(handle: *mut PontusHandle, scan_id: i64) -> bool {
    if handle.is_null() {
        return false;
    }
    let handle = unsafe { &*handle };
    handle.store.set_baseline(scan_id).is_ok()
}

/// The designated baseline scan id, or -1 if none is set (or on error).
///
/// # Safety
/// `handle` must be a valid handle from [`pontus_open`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pontus_baseline(handle: *mut PontusHandle) -> i64 {
    if handle.is_null() {
        return -1;
    }
    let handle = unsafe { &*handle };
    handle.store.baseline().ok().flatten().unwrap_or(-1)
}

/// Free a string returned by this library.
///
/// # Safety
/// `s` must be a pointer returned by a `pontus-ffi` function, freed at most once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pontus_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

// ---- internals ------------------------------------------------------------

/// Run `f` against a borrowed handle, returning its JSON as an owned C string (or
/// null on a null handle / failure).
fn with_handle<F>(handle: *mut PontusHandle, f: F) -> *mut c_char
where
    F: FnOnce(&PontusHandle) -> Option<String>,
{
    if handle.is_null() {
        return ptr::null_mut();
    }
    let handle = unsafe { &*handle };
    into_c_string(f(handle))
}

/// Convert an optional owned string into a heap C string, or null. A string with
/// an interior NUL (which cannot be a C string) also yields null.
fn into_c_string(s: Option<String>) -> *mut c_char {
    match s.and_then(|s| CString::new(s).ok()) {
        Some(c) => c.into_raw(),
        None => ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pontus_core::{IdentitySignals, ObservationState};

    fn temp_db() -> std::path::PathBuf {
        // Unique per test binary invocation; process id is enough here.
        std::env::temp_dir().join(format!("pontus-ffi-{}.db", std::process::id()))
    }

    /// Populate a store with one asset across two scans, returning the db path.
    fn seed(path: &std::path::Path) {
        let store = Store::open(path).unwrap();
        let sig = IdentitySignals {
            mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            ip: Some("192.168.1.5".parse().unwrap()),
            ..Default::default()
        };
        let s1 = store.begin_scan("192.168.1.0/24", "192.168.1.0/24", None).unwrap();
        store.record(&sig, s1, &ObservationState { up: true, ..Default::default() }).unwrap();
        store.finish_scan(s1).unwrap();
        let s2 = store.begin_scan("192.168.1.0/24", "192.168.1.0/24", None).unwrap();
        store.record(&sig, s2, &ObservationState { up: true, ..Default::default() }).unwrap();
        store.finish_scan(s2).unwrap();
    }

    fn read_and_free(ptr: *mut c_char) -> String {
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap().to_string();
        unsafe { pontus_string_free(ptr) };
        s
    }

    #[test]
    fn read_surface_round_trips_through_the_abi() {
        let path = temp_db();
        let _ = std::fs::remove_file(&path);
        seed(&path);

        let cpath = CString::new(path.to_str().unwrap()).unwrap();
        let handle = unsafe { pontus_open(cpath.as_ptr()) };
        assert!(!handle.is_null());

        let assets = read_and_free(unsafe { pontus_assets_json(handle) });
        assert!(assets.contains("aa:bb:cc:dd:ee:ff"), "asset identity in JSON: {assets}");

        let scans = read_and_free(unsafe { pontus_scans_json(handle, 10) });
        assert!(scans.contains("192.168.1.0/24"));

        let history = read_and_free(unsafe { pontus_asset_history_json(handle, 1) });
        // Two scans recorded two observations for the one asset.
        assert_eq!(history.matches("observed_at").count(), 2, "history: {history}");

        let diff = read_and_free(unsafe { pontus_diff_json(handle, 1, 2) });
        assert!(diff.contains("Unchanged"), "no drift between identical scans: {diff}");

        // Baseline write/read round-trip (F-014).
        assert_eq!(unsafe { pontus_baseline(handle) }, -1, "no baseline initially");
        assert!(unsafe { pontus_set_baseline(handle, 1) });
        assert_eq!(unsafe { pontus_baseline(handle) }, 1);

        unsafe { pontus_close(handle) };
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn null_inputs_are_safe() {
        assert!(unsafe { pontus_open(ptr::null()) }.is_null());
        assert!(unsafe { pontus_assets_json(ptr::null_mut()) }.is_null());
        unsafe { pontus_close(ptr::null_mut()) }; // no-op, must not crash
        unsafe { pontus_string_free(ptr::null_mut()) }; // no-op
    }

    #[test]
    fn version_is_reported() {
        let v = read_and_free(pontus_version());
        assert!(!v.is_empty());
    }
}
