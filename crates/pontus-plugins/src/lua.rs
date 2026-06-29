//! The Lua runner (mlua, D-003).
//!
//! A Lua plugin defines a global entry point `check(target)` that returns a list
//! of finding tables. The runner hands the [`Target`] over as a Lua value (via
//! serde), calls `check`, and decodes the returned tables straight back into
//! [`Finding`]s — no hand-written marshalling.
//!
//! Lua here is "lightweight built-ins" (D-003): the state is created with a
//! curated subset of the standard library — base plus `table`/`string`/`math`/
//! `coroutine`, but **no `io`, `os`, `package`/`require` or `debug`** — so a plugin
//! cannot reach the filesystem or the OS. A memory limit bounds runaway allocation.
//! (A CPU/instruction limit for runaway loops is a planned follow-up; the fully
//! untrusted path is the WASM runner, which gets wasmtime's fuel metering.)

use crate::finding::{Finding, Target};
use crate::plugin::{Language, Plugin, PluginError, PluginRunner};
use mlua::{Function, Lua, LuaOptions, LuaSerdeExt, StdLib, Value};

/// Default cap on Lua heap allocation per run.
const DEFAULT_MEMORY_LIMIT: usize = 64 * 1024 * 1024;
/// The global function every Lua plugin must define.
const ENTRYPOINT: &str = "check";

/// Runs Lua plugins under a curated, filesystem-free standard library.
pub struct LuaRunner {
    memory_limit: usize,
}

impl Default for LuaRunner {
    fn default() -> Self {
        LuaRunner { memory_limit: DEFAULT_MEMORY_LIMIT }
    }
}

impl LuaRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the per-run Lua heap limit (bytes).
    pub fn with_memory_limit(mut self, bytes: usize) -> Self {
        self.memory_limit = bytes;
        self
    }
}

impl PluginRunner for LuaRunner {
    fn language(&self) -> Language {
        Language::Lua
    }

    fn run(&self, plugin: &Plugin, target: &Target) -> Result<Vec<Finding>, PluginError> {
        let rt = |message: String| PluginError::Runtime { plugin: plugin.name.clone(), message };
        let conv =
            |message: String| PluginError::Conversion { plugin: plugin.name.clone(), message };

        // Curated built-ins only — base + table/string/math/coroutine. No io/os/
        // package/debug, so the plugin has no filesystem or OS surface.
        let libs = StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::COROUTINE;
        let lua = Lua::new_with(libs, LuaOptions::default()).map_err(|e| rt(e.to_string()))?;
        lua.set_memory_limit(self.memory_limit).map_err(|e| rt(e.to_string()))?;

        let code = plugin.code()?;
        lua.load(code.as_ref())
            .set_name(plugin.name.clone())
            .exec()
            .map_err(|e| rt(format!("load: {e}")))?;

        let check: Function = lua
            .globals()
            .get(ENTRYPOINT)
            .map_err(|_| conv(format!("no global function `{ENTRYPOINT}(target)`")))?;

        let target_val = lua
            .to_value(target)
            .map_err(|e| conv(format!("encoding target: {e}")))?;
        let ret: Value = check
            .call(target_val)
            .map_err(|e| rt(format!("{ENTRYPOINT}(): {e}")))?;

        // Returning nothing is valid — no findings.
        if ret.is_nil() {
            return Ok(Vec::new());
        }
        lua.from_value(ret)
            .map_err(|e| conv(format!("decoding findings: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use crate::plugin::{PluginHost, PluginSource};

    const TELNET: &str = r#"
        function check(target)
          local out = {}
          for _, p in ipairs(target.ports) do
            if p.proto == "tcp" and p.port == 23 then
              out[#out + 1] = {
                title = "Telnet exposed",
                severity = "high",
                description = "Port 23/tcp is open.",
                metadata = { port = "23" },
              }
            end
          end
          return out
        end
    "#;

    fn host() -> PluginHost {
        let mut h = PluginHost::new();
        h.register(Box::new(LuaRunner::new()));
        h
    }

    #[test]
    fn runs_a_plugin_and_returns_a_structured_finding() {
        let plugin = Plugin::inline("telnet", Language::Lua, TELNET);
        let target = Target::new("192.168.1.10").with_port(23, "tcp");

        let findings = host().run(&plugin, &target).unwrap();
        assert_eq!(findings.len(), 1);
        let f = &findings[0];
        assert_eq!(f.title, "Telnet exposed");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.plugin, "telnet", "host stamps the plugin name");
        assert_eq!(f.metadata.get("port").map(String::as_str), Some("23"));
    }

    #[test]
    fn no_match_returns_no_findings() {
        let plugin = Plugin::inline("telnet", Language::Lua, TELNET);
        let target = Target::new("192.168.1.10").with_port(22, "tcp");
        assert!(host().run(&plugin, &target).unwrap().is_empty());
    }

    #[test]
    fn returning_an_empty_table_is_no_findings() {
        let plugin = Plugin::inline("noop", Language::Lua, "function check(t) return {} end");
        assert!(host().run(&plugin, &Target::new("10.0.0.1")).unwrap().is_empty());
    }

    #[test]
    fn the_sandbox_denies_filesystem_access() {
        // `io` is not loaded, so indexing it is a runtime error — the plugin
        // cannot open files (D-003: Lua has no filesystem surface).
        let plugin = Plugin::inline(
            "evil",
            Language::Lua,
            r#"function check(t) local f = io.open("/etc/passwd", "r"); return {} end"#,
        );
        let err = host().run(&plugin, &Target::new("10.0.0.1")).unwrap_err();
        assert!(matches!(err, PluginError::Runtime { .. }), "got {err:?}");
        assert!(err.to_string().contains("io"), "error should point at the missing io: {err}");
    }

    #[test]
    fn os_library_is_also_absent() {
        let plugin = Plugin::inline("evil", Language::Lua, r#"function check(t) os.execute("id"); return {} end"#);
        assert!(host().run(&plugin, &Target::new("10.0.0.1")).is_err());
    }

    #[test]
    fn missing_entry_point_is_a_conversion_error() {
        let plugin = Plugin::inline("empty", Language::Lua, "local x = 1");
        let err = host().run(&plugin, &Target::new("10.0.0.1")).unwrap_err();
        assert!(matches!(err, PluginError::Conversion { .. }), "got {err:?}");
    }

    #[test]
    fn broken_syntax_is_a_runtime_error() {
        let plugin = Plugin::inline("bad", Language::Lua, "function check( this is not lua");
        assert!(host().run(&plugin, &Target::new("10.0.0.1")).is_err());
    }

    #[test]
    fn loads_the_example_plugin_from_disk() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/plugins/telnet.lua");
        let plugin = Plugin::from_path("telnet", Language::Lua, path);
        assert!(matches!(plugin.source, PluginSource::Path(_)));
        let target = Target::new("192.168.1.1").with_port(23, "tcp");
        let findings = host().run(&plugin, &target).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }
}
