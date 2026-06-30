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

    fn run(
        &self,
        plugin: &Plugin,
        target: &Target,
        caps: &dyn crate::capability::HostCapabilities,
    ) -> Result<Vec<Finding>, PluginError> {
        let rt = |message: String| PluginError::Runtime { plugin: plugin.name.clone(), message };
        let conv =
            |message: String| PluginError::Conversion { plugin: plugin.name.clone(), message };

        // Curated built-ins only — base + table/string/math/coroutine. No io/os/
        // package/debug, so the plugin has no filesystem or OS surface. Network
        // access is only via the host-mediated, scope-enforced `pontus.*` table.
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

        // A `scope` lets us register host functions that borrow `caps` for the
        // duration of the call without requiring a 'static closure.
        let findings = lua
            .scope(|scope| {
                let pontus = lua.create_table()?;
                let http_get = scope.create_function(|lua, url: String| {
                    let resp = caps.http_get(&url).map_err(mlua::Error::external)?;
                    let t = lua.create_table()?;
                    t.set("status", resp.status)?;
                    let headers = lua.create_table()?;
                    for (k, v) in resp.headers {
                        headers.set(k, v)?;
                    }
                    t.set("headers", headers)?;
                    t.set("body", resp.body)?;
                    Ok(t)
                })?;
                pontus.set("http_get", http_get)?;

                let snmp_get = scope.create_function(
                    |_lua, (host, community, oid): (String, String, String)| {
                        // nil when there's no answer; an error only on misuse.
                        caps.snmp_get(&host, &community, &oid).map_err(mlua::Error::external)
                    },
                )?;
                pontus.set("snmp_get", snmp_get)?;

                let ssh_hostkey = scope.create_function(|lua, (host, port): (String, u16)| {
                    let keys = caps.ssh_hostkey(&host, port).map_err(mlua::Error::external)?;
                    let arr = lua.create_table()?;
                    for (i, k) in keys.into_iter().enumerate() {
                        let t = lua.create_table()?;
                        t.set("algo", k.algo)?;
                        t.set("bits", k.bits)?;
                        t.set("fingerprint", k.fingerprint)?;
                        arr.set(i + 1, t)?;
                    }
                    Ok(arr)
                })?;
                pontus.set("ssh_hostkey", ssh_hostkey)?;

                let smb_shares = scope.create_function(|lua, host: String| {
                    let shares = caps.smb_shares(&host).map_err(mlua::Error::external)?;
                    let arr = lua.create_table()?;
                    for (i, s) in shares.into_iter().enumerate() {
                        let t = lua.create_table()?;
                        t.set("kind", s.kind)?;
                        t.set("name", s.name)?;
                        t.set("comment", s.comment)?;
                        arr.set(i + 1, t)?;
                    }
                    Ok(arr)
                })?;
                pontus.set("smb_shares", smb_shares)?;

                lua.globals().set("pontus", pontus)?;

                let target_val = lua.to_value(target)?;
                let ret: Value = check.call(target_val)?;
                if ret.is_nil() {
                    return Ok(Vec::new());
                }
                lua.from_value(ret)
            })
            .map_err(|e| rt(format!("{ENTRYPOINT}(): {e}")))?;
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapError, HostCapabilities, HttpResponse};
    use crate::finding::Severity;
    use crate::plugin::{PluginHost, PluginSource};
    use std::collections::BTreeMap;

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

    #[test]
    fn first_party_cleartext_services_flags_http_and_telnet() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/plugins/cleartext-services.lua");
        let plugin = Plugin::from_path("cleartext-services", Language::Lua, path);
        // A typical host: HTTP open (low), Telnet open (high), HTTPS open (ignored).
        let target = Target::new("192.168.1.1")
            .with_port(80, "tcp")
            .with_port(23, "tcp")
            .with_port(443, "tcp");
        let findings = host().run(&plugin, &target).unwrap();
        assert_eq!(findings.len(), 2, "HTTP + Telnet flagged, HTTPS ignored");
        assert!(findings.iter().any(|f| f.title.contains("Telnet") && f.severity == Severity::High));
        assert!(findings.iter().any(|f| f.title.contains("HTTP") && f.severity == Severity::Low));
    }

    // A stub capability returning a canned HTTP response, so the Lua↔capability
    // bridge can be tested without a network.
    struct StubHttp;
    impl HostCapabilities for StubHttp {
        fn http_get(&self, _url: &str) -> Result<HttpResponse, CapError> {
            let mut headers = BTreeMap::new();
            headers.insert("server".to_string(), "nginx/1.18.0".to_string());
            Ok(HttpResponse { status: 200, headers, body: "hi".to_string() })
        }
        fn snmp_get(&self, _host: &str, community: &str, _oid: &str) -> Result<Option<String>, CapError> {
            // Only the "public" community "answers", to exercise nil handling.
            Ok((community == "public").then(|| "Test Router v1".to_string()))
        }
        fn ssh_hostkey(&self, _host: &str, _port: u16) -> Result<Vec<crate::capability::SshHostKey>, CapError> {
            Ok(vec![
                crate::capability::SshHostKey { algo: "ED25519".into(), bits: 256, fingerprint: "SHA256:aaa".into() },
                crate::capability::SshHostKey { algo: "RSA".into(), bits: 1024, fingerprint: "SHA256:bbb".into() },
            ])
        }
        fn smb_shares(&self, _host: &str) -> Result<Vec<crate::capability::SmbShare>, CapError> {
            Ok(vec![
                crate::capability::SmbShare { kind: "Disk".into(), name: "backups".into(), comment: "".into() },
                crate::capability::SmbShare { kind: "IPC".into(), name: "IPC$".into(), comment: "IPC Service".into() },
            ])
        }
    }

    #[test]
    fn a_plugin_can_probe_via_the_http_capability() {
        let mut h = PluginHost::new();
        h.register(Box::new(LuaRunner::new()));
        let plugin = Plugin::inline(
            "hdr",
            Language::Lua,
            r#"function check(target)
                 local r = pontus.http_get("http://" .. target.ip .. "/")
                 local out = {}
                 if r.headers["server"] then
                   out[#out+1] = { title = "Server: " .. r.headers["server"],
                                   severity = "info", metadata = { status = tostring(r.status) } }
                 end
                 return out
               end"#,
        );
        let findings = h.run_with(&plugin, &Target::new("10.0.0.1"), &StubHttp).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("nginx/1.18.0"));
        assert_eq!(findings[0].metadata.get("status").map(String::as_str), Some("200"));
    }

    #[test]
    fn a_plugin_can_query_snmp_and_nil_is_handled() {
        let mut h = PluginHost::new();
        h.register(Box::new(LuaRunner::new()));
        let plugin = Plugin::inline(
            "snmp",
            Language::Lua,
            r#"function check(target)
                 local out = {}
                 local pub = pontus.snmp_get(target.ip, "public", "1.3.6.1.2.1.1.1.0")
                 local prv = pontus.snmp_get(target.ip, "private", "1.3.6.1.2.1.1.1.0")
                 if pub then out[#out+1] = { title = "SNMP public: " .. pub, severity = "medium" } end
                 if prv then out[#out+1] = { title = "SNMP private", severity = "medium" } end
                 return out
               end"#,
        );
        let findings = h.run_with(&plugin, &Target::new("10.0.0.1"), &StubHttp).unwrap();
        assert_eq!(findings.len(), 1, "only the public community answered (private → nil)");
        assert!(findings[0].title.contains("Test Router v1"));
    }

    #[test]
    fn first_party_ssh_hostkey_records_keys_and_flags_weak_rsa() {
        let mut h = PluginHost::new();
        h.register(Box::new(LuaRunner::new()));
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/plugins/ssh-hostkey.lua");
        let plugin = Plugin::from_path("ssh-hostkey", Language::Lua, path);
        let target = Target::new("10.0.0.1").with_port(22, "tcp");
        let findings = h.run_with(&plugin, &target, &StubHttp).unwrap();
        // Two key info findings + one weak-RSA (1024-bit) warning.
        assert_eq!(findings.iter().filter(|f| f.title.starts_with("SSH host key")).count(), 2);
        assert!(findings.iter().any(|f| f.title.contains("Weak SSH RSA") && f.severity == Severity::Medium));
        // No SSH port observed → nothing probed.
        let none = h.run_with(&plugin, &Target::new("10.0.0.1").with_port(80, "tcp"), &StubHttp).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn first_party_smb_enum_lists_shares_when_smb_is_open() {
        let mut h = PluginHost::new();
        h.register(Box::new(LuaRunner::new()));
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/plugins/smb-enum.lua");
        let plugin = Plugin::from_path("smb-enum", Language::Lua, path);

        let target = Target::new("10.0.0.1").with_port(445, "tcp");
        let findings = h.run_with(&plugin, &target, &StubHttp).unwrap();
        // One "anonymous enumeration" finding + one per share (2).
        assert!(findings.iter().any(|f| f.title.contains("Anonymous SMB") && f.severity == Severity::Medium));
        assert_eq!(findings.iter().filter(|f| f.title.starts_with("SMB share")).count(), 2);

        // No SMB port observed → nothing probed.
        assert!(h.run_with(&plugin, &Target::new("10.0.0.1").with_port(80, "tcp"), &StubHttp).unwrap().is_empty());
    }

    #[test]
    fn without_capabilities_http_get_errors() {
        // The default run() grants NoCapabilities, so a probing plugin fails rather
        // than reaching the network.
        let plugin = Plugin::inline(
            "hdr",
            Language::Lua,
            r#"function check(t) pontus.http_get("http://10.0.0.1/"); return {} end"#,
        );
        assert!(host().run(&plugin, &Target::new("10.0.0.1")).is_err());
    }

    #[test]
    fn first_party_snmp_info_probes_when_161_udp_is_open() {
        let mut h = PluginHost::new();
        h.register(Box::new(LuaRunner::new()));
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/plugins/snmp-info.lua");
        let plugin = Plugin::from_path("snmp-info", Language::Lua, path);

        // No 161/udp observed → the plugin does nothing (no wasted probes).
        let quiet = h.run_with(&plugin, &Target::new("10.0.0.1").with_port(80, "tcp"), &StubHttp).unwrap();
        assert!(quiet.is_empty());

        // With 161/udp observed, the stub answers the "public" community.
        let target = Target::new("10.0.0.1").with_port(161, "udp");
        let findings = h.run_with(&plugin, &target, &StubHttp).unwrap();
        assert!(!findings.is_empty());
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].title.contains("community 'public'"));
    }

    #[test]
    fn first_party_exposed_discovery_flags_upnp_over_udp() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/plugins/exposed-discovery.lua");
        let plugin = Plugin::from_path("exposed-discovery", Language::Lua, path);
        let target = Target::new("192.168.1.1").with_port(1900, "udp").with_port(22, "tcp");
        let findings = host().run(&plugin, &target).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].title.contains("UPnP"));
        assert_eq!(findings[0].metadata.get("proto").map(String::as_str), Some("udp"));
    }
}
