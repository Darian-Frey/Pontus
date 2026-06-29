//! `pontus-plugins` — the plugin host (F-020, D-003).
//!
//! One stable, serde-driven data contract ([`Finding`]/[`Target`]) and a
//! [`PluginRunner`] trait, with a runtime backend per language. The runners are
//! tiered by trust (D-003): Lua via mlua (lightweight, curated built-ins, here),
//! WASM via wasmtime (untrusted, sandboxed) and Python via pyo3 (trusted) to come.
//! [`PluginHost`] routes a [`Plugin`] to the runner for its [`Language`] and
//! stamps each finding with the producing plugin's name.

pub mod finding;
pub mod lua;
pub mod plugin;

pub use finding::{Finding, Severity, Target, TargetPort};
pub use lua::LuaRunner;
pub use plugin::{Language, Plugin, PluginError, PluginHost, PluginRunner, PluginSource};
