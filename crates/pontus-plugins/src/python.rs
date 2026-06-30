//! The Python runner (pyo3, D-003) — the **trusted, full-power** tier.
//!
//! Unlike the Lua (curated built-ins) and WASM (no host imports) runners, Python
//! plugins are **not sandboxed**: this tier is for trusted first-party / operator
//! plugins that need the full language and ecosystem (D-003). Run untrusted code in
//! the WASM tier instead.
//!
//! A Python plugin defines a top-level `check(target)` taking the target as a dict
//! and returning a list of finding dicts. JSON is the interchange (symmetric with
//! the WASM runner): the host hands the target in via `json.loads` and reads the
//! result back via `json.dumps`, so plugins work in plain dicts/lists with no
//! Pontus-specific bindings.
//!
//! Compiled only with `--features python` (it links libpython).

use crate::finding::{Finding, Target};
use crate::plugin::{Language, Plugin, PluginError, PluginRunner};
use pyo3::prelude::*;
use pyo3::types::PyAnyMethods;
use std::ffi::CString;

/// Runs Python plugins under an embedded CPython interpreter.
#[derive(Default)]
pub struct PythonRunner {
    _private: (),
}

impl PythonRunner {
    pub fn new() -> Self {
        PythonRunner::default()
    }
}

impl PluginRunner for PythonRunner {
    fn language(&self) -> Language {
        Language::Python
    }

    fn run(
        &self,
        plugin: &Plugin,
        target: &Target,
        _caps: &dyn crate::capability::HostCapabilities,
    ) -> Result<Vec<Finding>, PluginError> {
        // Python is the trusted, full-power tier and already has native network
        // access, so host capabilities aren't injected here.
        let rt = |message: String| PluginError::Runtime { plugin: plugin.name.clone(), message };
        let conv =
            |message: String| PluginError::Conversion { plugin: plugin.name.clone(), message };

        let code = plugin.code()?;
        let target_json = serde_json::to_string(target).map_err(|e| conv(e.to_string()))?;

        // CStrings for pyo3's from_code (code / file name / module name).
        let cstr = |s: &str| {
            CString::new(s).map_err(|_| PluginError::Load("plugin source contains a NUL byte".into()))
        };
        let code_c = cstr(code.as_ref())?;
        let file_c = cstr(&format!("{}.py", plugin.name))?;
        let name_c = cstr(&plugin.name)?;

        let out_json: Result<String, PluginError> = Python::with_gil(|py| {
            let module =
                PyModule::from_code(py, code_c.as_c_str(), file_c.as_c_str(), name_c.as_c_str())
                    .map_err(|e| rt(format!("load: {e}")))?;
            let check = module
                .getattr("check")
                .map_err(|_| conv("no top-level `check(target)` function".into()))?;

            let json = py.import("json").map_err(|e| rt(e.to_string()))?;
            let target_obj = json
                .call_method1("loads", (target_json.as_str(),))
                .map_err(|e| conv(format!("encoding target: {e}")))?;
            let result = check
                .call1((target_obj,))
                .map_err(|e| rt(format!("check(): {e}")))?;
            json.call_method1("dumps", (result,))
                .and_then(|o| o.extract::<String>())
                .map_err(|e| conv(format!("decoding findings: {e}")))
        });
        let out_json = out_json?;

        let trimmed = out_json.trim();
        if trimmed.is_empty() || trimmed == "null" {
            return Ok(Vec::new());
        }
        serde_json::from_str(trimmed).map_err(|e| conv(format!("decoding findings: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;
    use crate::plugin::PluginHost;

    const TELNET: &str = r#"
def check(target):
    out = []
    for p in target["ports"]:
        if p["proto"] == "tcp" and p["port"] == 23:
            out.append({
                "title": "Telnet exposed",
                "severity": "high",
                "description": "Port 23/tcp is open.",
                "metadata": {"port": "23"},
            })
    return out
"#;

    fn host() -> PluginHost {
        let mut h = PluginHost::new();
        h.register(Box::new(PythonRunner::new()));
        h
    }

    #[test]
    fn runs_a_plugin_and_returns_a_structured_finding() {
        let plugin = Plugin::inline("telnet", Language::Python, TELNET);
        let target = Target::new("192.168.1.10").with_port(23, "tcp");
        let findings = host().run(&plugin, &target).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Telnet exposed");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].plugin, "telnet", "host stamps the plugin name");
        assert_eq!(findings[0].metadata.get("port").map(String::as_str), Some("23"));
    }

    #[test]
    fn no_match_returns_no_findings() {
        let plugin = Plugin::inline("telnet", Language::Python, TELNET);
        let target = Target::new("192.168.1.10").with_port(22, "tcp");
        assert!(host().run(&plugin, &target).unwrap().is_empty());
    }

    #[test]
    fn returning_none_is_no_findings() {
        let plugin = Plugin::inline("noop", Language::Python, "def check(target):\n    return None\n");
        assert!(host().run(&plugin, &Target::new("10.0.0.1")).unwrap().is_empty());
    }

    #[test]
    fn missing_entry_point_is_a_conversion_error() {
        let plugin = Plugin::inline("empty", Language::Python, "x = 1\n");
        let err = host().run(&plugin, &Target::new("10.0.0.1")).unwrap_err();
        assert!(matches!(err, PluginError::Conversion { .. }), "got {err:?}");
    }

    #[test]
    fn an_exception_is_a_runtime_error() {
        let plugin = Plugin::inline(
            "boom",
            Language::Python,
            "def check(target):\n    raise ValueError('nope')\n",
        );
        let err = host().run(&plugin, &Target::new("10.0.0.1")).unwrap_err();
        assert!(matches!(err, PluginError::Runtime { .. }), "got {err:?}");
    }

    #[test]
    fn loads_the_example_plugin_from_disk() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/plugins/telnet.py");
        let plugin = Plugin::from_path("telnet", Language::Python, path);
        let target = Target::new("192.168.1.1").with_port(23, "tcp");
        let findings = host().run(&plugin, &target).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }
}
