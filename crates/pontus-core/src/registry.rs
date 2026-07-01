//! Plugin registry (F-026) — install first-party/community plugins from a
//! git-hosted registry with **ed25519 signature verification**. A registry is an
//! `index.json` plus the plugin files, served either over HTTP(S) (e.g. raw git
//! URLs) or from a local directory (for testing/offline mirrors). Every plugin
//! carries a signature over its bytes; on install Pontus verifies it against a
//! trusted registry public key and **refuses anything that doesn't verify**.
//!
//! Signing uses ed25519 (ed25519-dalek — pure Rust, no OpenSSL). Keys and
//! signatures are hex-encoded (dependency-free). `keygen`/`sign` are maintainer
//! tools; `fetch_index`/`install` are the client side.

use crate::error::{Error, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// One plugin advertised by a registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginEntry {
    pub name: String,
    pub language: String,
    #[serde(default)]
    pub description: String,
    /// File name within the registry (also the installed name).
    pub file: String,
    /// Hex-encoded ed25519 signature over the plugin file's bytes.
    pub signature: String,
}

/// A registry index (`index.json`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RegistryIndex {
    #[serde(default)]
    pub plugins: Vec<PluginEntry>,
}

/// A freshly generated signing keypair (hex-encoded), for a registry maintainer.
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub public_hex: String,
    pub secret_hex: String,
}

/// Generate an ed25519 keypair. The 32-byte seed is the secret.
pub fn keygen() -> Result<KeyPair> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| Error::Parse(format!("rng: {e}")))?;
    let sk = SigningKey::from_bytes(&seed);
    let pair = KeyPair { public_hex: hex_encode(sk.verifying_key().as_bytes()), secret_hex: hex_encode(&seed) };
    Ok(pair)
}

/// Sign `data` with a hex secret seed, returning the hex signature.
pub fn sign(secret_hex: &str, data: &[u8]) -> Result<String> {
    let seed = hex_decode(secret_hex).and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or_else(|| Error::Parse("secret key must be 32 hex-encoded bytes".into()))?;
    let sk = SigningKey::from_bytes(&seed);
    Ok(hex_encode(&sk.sign(data).to_bytes()))
}

/// Verify a hex ed25519 signature over `data` against a hex public key.
pub fn verify(public_hex: &str, data: &[u8], signature_hex: &str) -> bool {
    let Some(pk) = hex_decode(public_hex).and_then(|v| <[u8; 32]>::try_from(v).ok()) else {
        return false;
    };
    let Some(sig) = hex_decode(signature_hex).and_then(|v| <[u8; 64]>::try_from(v).ok()) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    vk.verify_strict(data, &Signature::from_bytes(&sig)).is_ok()
}

/// Read a path relative to a registry (an HTTP base URL or a local directory).
fn read_registry(registry: &str, rel: &str, timeout: Duration) -> Result<Vec<u8>> {
    if registry.starts_with("http://") || registry.starts_with("https://") {
        let url = format!("{}/{}", registry.trim_end_matches('/'), rel);
        let agent = ureq::AgentBuilder::new().timeout(timeout).build();
        let resp = agent.get(&url).call().map_err(|e| Error::Http(e.to_string()))?;
        let mut buf = Vec::new();
        resp.into_reader().read_to_end(&mut buf)?;
        Ok(buf)
    } else {
        Ok(std::fs::read(Path::new(registry).join(rel))?)
    }
}

/// Fetch and parse a registry's index.
pub fn fetch_index(registry: &str, timeout: Duration) -> Result<RegistryIndex> {
    let raw = read_registry(registry, "index.json", timeout)?;
    serde_json::from_slice(&raw).map_err(|e| Error::Parse(format!("registry index: {e}")))
}

/// Install a plugin by name: fetch it, verify its signature against `public_hex`,
/// and — only if it verifies — write it into `dest_dir`, returning the path. An
/// unsigned or tampered plugin is refused (no file is written).
pub fn install(
    registry: &str,
    name: &str,
    public_hex: &str,
    dest_dir: &Path,
    timeout: Duration,
) -> Result<PathBuf> {
    let index = fetch_index(registry, timeout)?;
    let entry = index
        .plugins
        .iter()
        .find(|p| p.name == name)
        .ok_or_else(|| Error::NotFound(format!("plugin {name:?} in registry")))?;

    let data = read_registry(registry, &entry.file, timeout)?;
    if !verify(public_hex, &data, &entry.signature) {
        return Err(Error::Parse(format!(
            "signature verification failed for {name:?} — refusing to install"
        )));
    }

    std::fs::create_dir_all(dest_dir)?;
    let dest = dest_dir.join(&entry.file);
    std::fs::write(&dest, &data)?;
    Ok(dest)
}

// --- dependency-free hex ---

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    let b = s.as_bytes();
    (0..b.len() / 2).map(|i| Some((val(b[2 * i])? << 4) | val(b[2 * i + 1])?)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let data = [0x00, 0x0f, 0xa5, 0xff];
        assert_eq!(hex_encode(&data), "000fa5ff");
        assert_eq!(hex_decode("000fa5ff").unwrap(), data);
        assert!(hex_decode("xyz").is_none());
        assert!(hex_decode("abc").is_none()); // odd length
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let kp = keygen().unwrap();
        let data = b"function check(t) return {} end";
        let sig = sign(&kp.secret_hex, data).unwrap();
        assert!(verify(&kp.public_hex, data, &sig), "valid signature verifies");
        // Tampered data → fails.
        assert!(!verify(&kp.public_hex, b"function check(t) return {1} end", &sig));
        // Wrong key → fails.
        let other = keygen().unwrap();
        assert!(!verify(&other.public_hex, data, &sig));
        // Garbage signature → fails, doesn't panic.
        assert!(!verify(&kp.public_hex, data, "deadbeef"));
    }

    fn write_local_registry(dir: &Path, kp: &KeyPair, plugin: &str, body: &[u8]) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(plugin), body).unwrap();
        let sig = sign(&kp.secret_hex, body).unwrap();
        let index = RegistryIndex {
            plugins: vec![PluginEntry {
                name: "demo".into(),
                language: "lua".into(),
                description: "demo plugin".into(),
                file: plugin.into(),
                signature: sig,
            }],
        };
        std::fs::write(dir.join("index.json"), serde_json::to_vec(&index).unwrap()).unwrap();
    }

    fn tmp(sub: &str) -> PathBuf {
        std::env::temp_dir().join(format!("pontus-reg-{}-{sub}", std::process::id()))
    }

    #[test]
    fn install_verifies_and_writes_a_signed_plugin() {
        let kp = keygen().unwrap();
        let reg = tmp("reg");
        let _ = std::fs::remove_dir_all(&reg);
        write_local_registry(&reg, &kp, "demo.lua", b"function check(t) return {} end");

        let dest = tmp("plugins");
        let _ = std::fs::remove_dir_all(&dest);
        let path = install(reg.to_str().unwrap(), "demo", &kp.public_hex, &dest, Duration::from_secs(2)).unwrap();
        assert!(path.exists());
        assert_eq!(std::fs::read(&path).unwrap(), b"function check(t) return {} end");

        let _ = std::fs::remove_dir_all(&reg);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn install_refuses_a_tampered_plugin() {
        let kp = keygen().unwrap();
        let reg = tmp("reg2");
        let _ = std::fs::remove_dir_all(&reg);
        write_local_registry(&reg, &kp, "demo.lua", b"good plugin");
        // Tamper the file after signing.
        std::fs::write(reg.join("demo.lua"), b"EVIL plugin").unwrap();

        let dest = tmp("plugins2");
        let _ = std::fs::remove_dir_all(&dest);
        let err = install(reg.to_str().unwrap(), "demo", &kp.public_hex, &dest, Duration::from_secs(2)).unwrap_err();
        assert!(matches!(err, Error::Parse(_)));
        assert!(!dest.join("demo.lua").exists(), "nothing is written when verification fails");

        let _ = std::fs::remove_dir_all(&reg);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn install_with_a_wrong_key_is_refused() {
        let signer = keygen().unwrap();
        let attacker_view = keygen().unwrap(); // client trusts a different key
        let reg = tmp("reg3");
        let _ = std::fs::remove_dir_all(&reg);
        write_local_registry(&reg, &signer, "demo.lua", b"plugin");

        let dest = tmp("plugins3");
        let _ = std::fs::remove_dir_all(&dest);
        assert!(install(reg.to_str().unwrap(), "demo", &attacker_view.public_hex, &dest, Duration::from_secs(2)).is_err());

        let _ = std::fs::remove_dir_all(&reg);
        let _ = std::fs::remove_dir_all(&dest);
    }
}
