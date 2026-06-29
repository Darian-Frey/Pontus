//! Plugin description, the runner trait, and the host that dispatches a plugin to
//! the runner for its language (D-003). One stable interface, many runtimes.

use crate::finding::{Finding, Target};
use std::borrow::Cow;
use std::path::PathBuf;

/// The runtime a plugin is written for. Each maps to one [`PluginRunner`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    /// Lua via mlua — lightweight, curated built-ins (no filesystem/OS).
    Lua,
    /// WASM via wasmtime — untrusted, fully sandboxed (no ambient FS/network).
    Wasm,
    /// Python via pyo3 — trusted, full-power.
    Python,
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Language::Lua => "lua",
            Language::Wasm => "wasm",
            Language::Python => "python",
        })
    }
}

/// Where a plugin's code comes from.
#[derive(Debug, Clone)]
pub enum PluginSource {
    /// Source held in memory (tests, generated plugins).
    Inline(String),
    /// Source on disk, read at run time.
    Path(PathBuf),
}

/// A loaded plugin: a name, the language it is written in, and its source.
#[derive(Debug, Clone)]
pub struct Plugin {
    pub name: String,
    pub language: Language,
    pub source: PluginSource,
}

impl Plugin {
    /// An inline plugin (handy for tests and embedding).
    pub fn inline(name: impl Into<String>, language: Language, code: impl Into<String>) -> Self {
        Plugin { name: name.into(), language, source: PluginSource::Inline(code.into()) }
    }

    /// A plugin loaded from a file. The language is the caller's responsibility.
    pub fn from_path(name: impl Into<String>, language: Language, path: impl Into<PathBuf>) -> Self {
        Plugin { name: name.into(), language, source: PluginSource::Path(path.into()) }
    }

    /// The plugin's source code, reading the file if needed.
    pub fn code(&self) -> Result<Cow<'_, str>, PluginError> {
        match &self.source {
            PluginSource::Inline(s) => Ok(Cow::Borrowed(s.as_str())),
            PluginSource::Path(p) => std::fs::read_to_string(p)
                .map(Cow::Owned)
                .map_err(|e| PluginError::Load(format!("{}: {e}", p.display()))),
        }
    }
}

/// What can go wrong running a plugin.
#[derive(Debug, thiserror::Error)]
pub enum PluginError {
    /// No registered runner handles the plugin's language.
    #[error("no runner registered for {0}")]
    UnsupportedLanguage(Language),
    /// Reading/compiling the plugin source failed.
    #[error("loading plugin: {0}")]
    Load(String),
    /// The plugin raised an error or misbehaved while running.
    #[error("running plugin {plugin:?}: {message}")]
    Runtime { plugin: String, message: String },
    /// The plugin returned something that isn't a valid finding set.
    #[error("plugin {plugin:?} returned an invalid result: {message}")]
    Conversion { plugin: String, message: String },
}

/// One runtime backend. A runner handles exactly one [`Language`]; the host owns
/// the set and routes each plugin to the matching one.
pub trait PluginRunner: Send + Sync {
    /// The language this runner executes.
    fn language(&self) -> Language;
    /// Run `plugin` against `target`, returning its findings. Implementations
    /// should not stamp `Finding::plugin` — the host does that uniformly.
    fn run(&self, plugin: &Plugin, target: &Target) -> Result<Vec<Finding>, PluginError>;
}

/// Holds the registered runners and dispatches plugins by language.
#[derive(Default)]
pub struct PluginHost {
    runners: Vec<Box<dyn PluginRunner>>,
}

impl PluginHost {
    pub fn new() -> Self {
        PluginHost::default()
    }

    /// Register a runner. Later registrations for a language shadow earlier ones.
    pub fn register(&mut self, runner: Box<dyn PluginRunner>) -> &mut Self {
        self.runners.push(runner);
        self
    }

    /// Run a plugin against a target. Routes to the runner for the plugin's
    /// language, then stamps each finding with the plugin's name.
    pub fn run(&self, plugin: &Plugin, target: &Target) -> Result<Vec<Finding>, PluginError> {
        let runner = self
            .runners
            .iter()
            .rev()
            .find(|r| r.language() == plugin.language)
            .ok_or(PluginError::UnsupportedLanguage(plugin.language))?;
        let mut findings = runner.run(plugin, target)?;
        for f in &mut findings {
            f.plugin = plugin.name.clone();
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unregistered_language_is_an_error() {
        let host = PluginHost::new();
        let plugin = Plugin::inline("p", Language::Python, "");
        let err = host.run(&plugin, &Target::new("10.0.0.1")).unwrap_err();
        assert!(matches!(err, PluginError::UnsupportedLanguage(Language::Python)));
    }
}
