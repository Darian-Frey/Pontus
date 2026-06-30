//! The WASM runner (wasmtime, D-003) — the untrusted, fully-sandboxed tier.
//!
//! Untrusted community plugins run here with **no ambient authority**. The runner
//! links *no* host imports at all, so a module physically has no host function to
//! call: it cannot touch the filesystem, the network, the clock or the
//! environment. That guarantee is structural, not a configured policy — a module
//! that even *imports* a WASI function fails to instantiate. wasmtime **fuel**
//! bounds CPU (runaway loops trap) and a [`StoreLimits`] memory cap bounds growth.
//!
//! ABI (the contract a guest implements):
//! - export `memory`;
//! - export `run(target_ptr: i32, target_len: i32) -> i64` — read the target JSON
//!   from `[target_ptr, target_ptr+target_len)`, do its work, and return a packed
//!   `(result_ptr << 32) | result_len` pointing at a findings JSON array in its own
//!   memory (return `0` for no findings);
//! - optionally export `alloc(len: i32) -> i32` so the host can place the target
//!   JSON into guest memory (a guest that ignores the target may omit it).
//!
//! Both `.wasm` binaries and `.wat` text are accepted (wasmtime parses either).

use crate::finding::{Finding, Target};
use crate::plugin::{Language, Plugin, PluginError, PluginRunner};
use wasmtime::{Config, Engine, Instance, Memory, Module, Store, StoreLimits, StoreLimitsBuilder};

/// Default per-run fuel (≈ one unit per executed wasm operation): enough for real
/// work, but a runaway loop exhausts it and traps.
const DEFAULT_FUEL: u64 = 200_000_000;
/// Default cap on guest linear memory (bytes).
const DEFAULT_MEMORY_LIMIT: usize = 64 * 1024 * 1024;

/// Per-store host state: just the resource limiter.
struct HostState {
    limits: StoreLimits,
}

/// Runs WASM plugins under wasmtime with no imports, fuel metering and a memory cap.
pub struct WasmRunner {
    engine: Engine,
    fuel: u64,
    memory_limit: usize,
}

impl WasmRunner {
    pub fn new() -> Self {
        let mut config = Config::new();
        config.consume_fuel(true);
        // `Engine::new` only fails on an invalid config; ours is static and valid.
        let engine = Engine::new(&config).expect("valid wasmtime config");
        WasmRunner { engine, fuel: DEFAULT_FUEL, memory_limit: DEFAULT_MEMORY_LIMIT }
    }

    pub fn with_fuel(mut self, fuel: u64) -> Self {
        self.fuel = fuel;
        self
    }

    pub fn with_memory_limit(mut self, bytes: usize) -> Self {
        self.memory_limit = bytes;
        self
    }
}

impl Default for WasmRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginRunner for WasmRunner {
    fn language(&self) -> Language {
        Language::Wasm
    }

    fn run(
        &self,
        plugin: &Plugin,
        target: &Target,
        _caps: &dyn crate::capability::HostCapabilities,
    ) -> Result<Vec<Finding>, PluginError> {
        // The untrusted WASM tier stays import-free; host capabilities are not
        // exposed here (a future mediated import is possible — see F-021 notes).
        let rt = |message: String| PluginError::Runtime { plugin: plugin.name.clone(), message };
        let conv =
            |message: String| PluginError::Conversion { plugin: plugin.name.clone(), message };

        let bytes = plugin.bytes()?;
        let module = Module::new(&self.engine, bytes.as_ref())
            .map_err(|e| PluginError::Load(format!("{}: {e}", plugin.name)))?;

        let state = HostState {
            limits: StoreLimitsBuilder::new().memory_size(self.memory_limit).build(),
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limits);
        store.set_fuel(self.fuel).map_err(|e| rt(e.to_string()))?;

        // No imports: an untrusted module gets zero host capabilities. A module that
        // imports anything (e.g. a WASI call) fails here.
        let instance = Instance::new(&mut store, &module, &[])
            .map_err(|e| rt(format!("instantiate: {e}")))?;

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| conv("plugin exports no `memory`".into()))?;
        let run = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "run")
            .map_err(|_| conv("plugin exports no `run(i32, i32) -> i64`".into()))?;

        // Hand the target JSON to the guest via its allocator, if it has one.
        let target_json = serde_json::to_vec(target).map_err(|e| conv(e.to_string()))?;
        let (tptr, tlen) =
            match instance.get_typed_func::<i32, i32>(&mut store, "alloc") {
                Ok(alloc) => {
                    let len = i32::try_from(target_json.len())
                        .map_err(|_| conv("target too large for the guest".into()))?;
                    let ptr = alloc.call(&mut store, len).map_err(|e| rt(format!("alloc: {e}")))?;
                    write_guest(&memory, &mut store, ptr, &target_json)
                        .map_err(|e| rt(format!("writing target: {e}")))?;
                    (ptr, len)
                }
                Err(_) => (0, 0),
            };

        let packed = run.call(&mut store, (tptr, tlen)).map_err(|e| rt(format!("run: {e}")))?;
        let ptr = (packed >> 32) as u32 as usize;
        let len = (packed & 0xffff_ffff) as u32 as usize;
        if len == 0 {
            return Ok(Vec::new());
        }

        let data = memory.data(&store);
        let slice = data
            .get(ptr..ptr.saturating_add(len))
            .ok_or_else(|| conv("result pointer/length out of bounds".into()))?;
        serde_json::from_slice(slice).map_err(|e| conv(format!("decoding findings: {e}")))
    }
}

/// Copy `bytes` into guest memory at `ptr`, bounds-checked against the guest's
/// current memory size.
fn write_guest(
    memory: &Memory,
    store: &mut Store<HostState>,
    ptr: i32,
    bytes: &[u8],
) -> Result<(), String> {
    let ptr = usize::try_from(ptr).map_err(|_| "negative pointer".to_string())?;
    let data = memory.data_mut(store);
    let end = ptr.checked_add(bytes.len()).ok_or("pointer overflow")?;
    let dst = data.get_mut(ptr..end).ok_or("allocation out of bounds")?;
    dst.copy_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use crate::plugin::PluginHost;

    /// Build a WAT plugin whose `run` ignores the target and returns a constant
    /// findings JSON. The JSON and its byte length are computed in Rust so the
    /// data segment and the packed return length always agree.
    fn constant_findings_wat(json: &str) -> String {
        let escaped = json.replace('\\', "\\\\").replace('"', "\\\"");
        let len = json.len();
        format!(
            r#"(module
              (memory (export "memory") 1)
              (global $bump (mut i32) (i32.const 4096))
              (data (i32.const 256) "{escaped}")
              (func (export "alloc") (param $n i32) (result i32)
                (local $p i32)
                (local.set $p (global.get $bump))
                (global.set $bump (i32.add (global.get $bump) (local.get $n)))
                (local.get $p))
              (func (export "run") (param i32 i32) (result i64)
                (i64.or
                  (i64.shl (i64.const 256) (i64.const 32))
                  (i64.const {len}))))"#
        )
    }

    fn host() -> PluginHost {
        let mut h = PluginHost::new();
        h.register(Box::new(WasmRunner::new()));
        h
    }

    #[test]
    fn runs_a_wasm_plugin_and_returns_structured_findings() {
        let wat = constant_findings_wat(r#"[{"title":"wasm finding","severity":"medium"}]"#);
        let plugin = Plugin::inline("w", Language::Wasm, wat);
        let findings = host().run(&plugin, &Target::new("10.0.0.1").with_port(23, "tcp")).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "wasm finding");
        assert_eq!(findings[0].severity, Severity::Medium);
        assert_eq!(findings[0].plugin, "w", "host stamps the plugin name");
    }

    #[test]
    fn zero_return_is_no_findings() {
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "run") (param i32 i32) (result i64) (i64.const 0)))"#;
        let plugin = Plugin::inline("empty", Language::Wasm, wat);
        assert!(host().run(&plugin, &Target::new("10.0.0.1")).unwrap().is_empty());
    }

    #[test]
    fn a_module_that_imports_wasi_cannot_instantiate() {
        // The runner links no imports, so requesting any host capability is fatal —
        // an untrusted plugin gets no ambient filesystem/network authority (D-003).
        let wat = r#"(module
            (import "wasi_snapshot_preview1" "fd_write"
              (func (param i32 i32 i32 i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "run") (param i32 i32) (result i64) (i64.const 0)))"#;
        let plugin = Plugin::inline("evil", Language::Wasm, wat);
        let err = host().run(&plugin, &Target::new("10.0.0.1")).unwrap_err();
        assert!(matches!(err, PluginError::Runtime { .. }), "got {err:?}");
        assert!(
            err.to_string().contains("import") || err.to_string().contains("fd_write"),
            "should fail on the unsatisfied import: {err}"
        );
    }

    #[test]
    fn a_runaway_loop_is_stopped_by_fuel() {
        // `run` loops forever; fuel metering must trap it rather than hang.
        let wat = r#"(module
            (memory (export "memory") 1)
            (func (export "run") (param i32 i32) (result i64)
              (loop $l (br $l))
              (i64.const 0)))"#;
        let plugin = Plugin::inline("spin", Language::Wasm, wat);
        let err = host().run(&plugin, &Target::new("10.0.0.1")).unwrap_err();
        assert!(matches!(err, PluginError::Runtime { .. }), "got {err:?}");
    }

    #[test]
    fn missing_memory_export_is_a_conversion_error() {
        let wat = r#"(module
            (func (export "run") (param i32 i32) (result i64) (i64.const 0)))"#;
        let plugin = Plugin::inline("nomem", Language::Wasm, wat);
        let err = host().run(&plugin, &Target::new("10.0.0.1")).unwrap_err();
        assert!(matches!(err, PluginError::Conversion { .. }), "got {err:?}");
    }
}
