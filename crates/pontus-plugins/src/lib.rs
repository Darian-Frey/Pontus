//! `pontus-plugins` — the plugin host (F-020, D-003).
//!
//! One stable, serde-driven data contract ([`Finding`]/[`Target`]) and a
//! [`PluginRunner`] trait, with a runtime backend per language. The runners are
//! tiered by trust (D-003): Lua via mlua (lightweight, curated built-ins), WASM
//! via wasmtime (untrusted, fully sandboxed — no host imports), and Python via
//! pyo3 (trusted, full-power; opt-in behind the `python` feature as it links
//! libpython).
//! [`PluginHost`] routes a [`Plugin`] to the runner for its [`Language`] and
//! stamps each finding with the producing plugin's name.

pub mod capability;
pub mod finding;
pub mod lua;
pub mod plugin;
#[cfg(feature = "python")]
pub mod python;
pub mod wasm;

pub use capability::{CapError, HostCapabilities, HttpResponse, NetCapabilities, NoCapabilities};
pub use finding::{Finding, Severity, Target, TargetPort};
pub use lua::LuaRunner;
pub use plugin::{Language, Plugin, PluginError, PluginHost, PluginRunner, PluginSource};
#[cfg(feature = "python")]
pub use python::PythonRunner;
pub use wasm::WasmRunner;
