//! Credentialed scanning (F-022) — inventory depth using **user-supplied**
//! credentials. Pontus never guesses or cracks credentials (a non-goal); it logs
//! in with what the operator provides and reads inventory back.
//!
//! SSH is performed by shelling out to the user's own `ssh` (and `sshpass` for
//! password auth), the same "use the user's tool" posture as the Nmap-backed
//! detector (D-006): no SSH/crypto dependency is pulled into the tree, and the
//! user's existing config, agent and `known_hosts` apply. A single read-only
//! remote command reports the OS and the installed-package list; the output is
//! parsed here into structured [`SshInventory`].

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

/// One installed package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub version: String,
}

/// What a credentialed SSH pass gathered from a host.
#[derive(Debug, Clone, Default)]
pub struct SshInventory {
    /// OS description from `/etc/os-release` (e.g. "Ubuntu 22.04.4 LTS"), if read.
    pub os: Option<String>,
    /// The package manager the host uses (`dpkg`/`rpm`/`pacman`/`apk`/`none`).
    pub manager: Option<String>,
    pub packages: Vec<Package>,
}

/// Connection/auth options for an SSH inventory pass. Credentials are always
/// supplied by the caller — never discovered.
#[derive(Debug, Clone)]
pub struct SshOptions {
    pub user: String,
    pub port: u16,
    /// Identity (private key) file for key auth (`ssh -i`); `None` uses the agent
    /// / default keys.
    pub identity_file: Option<PathBuf>,
    /// Password for password auth (sent via `sshpass`, never on the command line);
    /// `None` means key/agent auth only.
    pub password: Option<String>,
    pub connect_timeout: Duration,
    /// `true` ⇒ `StrictHostKeyChecking=accept-new` (trust-on-first-use); `false` ⇒
    /// `=yes` (the host must already be in `known_hosts`).
    pub accept_new_host_keys: bool,
}

impl Default for SshOptions {
    fn default() -> Self {
        SshOptions {
            user: String::new(),
            port: 22,
            identity_file: None,
            password: None,
            connect_timeout: Duration::from_secs(10),
            accept_new_host_keys: true,
        }
    }
}

/// What can go wrong gathering inventory over SSH.
#[derive(Debug, thiserror::Error)]
pub enum CredError {
    #[error("could not launch {0} (is it installed? password auth needs `sshpass`)")]
    Spawn(String),
    #[error("ssh to {host} failed{code}: {stderr}")]
    Ssh { host: String, code: String, stderr: String },
}

/// A single read-only command: print the OS line, then the package manager and
/// one `PKG\tname\tversion` line per package. Tab-delimited so parsing is trivial
/// and unambiguous. Runs under the remote login shell.
const REMOTE_SCRIPT: &str = r#"
{ . /etc/os-release 2>/dev/null || true; printf 'OS\t%s\n' "${PRETTY_NAME:-${NAME:-unknown} ${VERSION_ID:-}}"; }
if command -v dpkg-query >/dev/null 2>&1; then printf 'MGR\tdpkg\n'; dpkg-query -W -f='PKG\t${Package}\t${Version}\n'
elif command -v rpm >/dev/null 2>&1; then printf 'MGR\trpm\n'; rpm -qa --qf 'PKG\t%{NAME}\t%{VERSION}-%{RELEASE}\n'
elif command -v pacman >/dev/null 2>&1; then printf 'MGR\tpacman\n'; pacman -Q 2>/dev/null | awk '{print "PKG\t"$1"\t"$2}'
elif command -v apk >/dev/null 2>&1; then printf 'MGR\tapk\n'; apk info -v 2>/dev/null | awk '{print "PKG\t"$0"\t"}'
else printf 'MGR\tnone\n'
fi
"#;

/// Gather installed-package inventory from `host` over SSH using user-supplied
/// credentials. Shells out to the system `ssh` (via `sshpass` for password auth).
pub fn gather_ssh_inventory(host: &str, opts: &SshOptions) -> Result<SshInventory, CredError> {
    let mut cmd = if let Some(pw) = &opts.password {
        // -e reads the password from $SSHPASS, keeping it off the argv / ps output.
        let mut c = Command::new("sshpass");
        c.arg("-e").env("SSHPASS", pw).arg("ssh");
        c
    } else {
        Command::new("ssh")
    };

    cmd.arg("-p").arg(opts.port.to_string());
    if opts.password.is_none() {
        // Key/agent auth only: never block on an interactive prompt.
        cmd.arg("-o").arg("BatchMode=yes");
    }
    cmd.arg("-o").arg(format!("ConnectTimeout={}", opts.connect_timeout.as_secs().max(1)));
    let strict = if opts.accept_new_host_keys { "accept-new" } else { "yes" };
    cmd.arg("-o").arg(format!("StrictHostKeyChecking={strict}"));
    if let Some(key) = &opts.identity_file {
        cmd.arg("-i").arg(key);
    }
    cmd.arg(format!("{}@{host}", opts.user));
    cmd.arg(REMOTE_SCRIPT);

    let program = if opts.password.is_some() { "sshpass" } else { "ssh" };
    let out = cmd.output().map_err(|_| CredError::Spawn(program.to_string()))?;
    if !out.status.success() {
        return Err(CredError::Ssh {
            host: host.to_string(),
            code: out.status.code().map(|c| format!(" (exit {c})")).unwrap_or_default(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(parse_inventory(&String::from_utf8_lossy(&out.stdout)))
}

/// Parse the tab-delimited remote output into an [`SshInventory`].
pub fn parse_inventory(stdout: &str) -> SshInventory {
    let mut inv = SshInventory::default();
    for line in stdout.lines() {
        let mut f = line.splitn(3, '\t');
        match f.next() {
            Some("OS") => {
                let os = f.next().unwrap_or("").trim();
                if !os.is_empty() && os != "unknown" {
                    inv.os = Some(os.to_string());
                }
            }
            Some("MGR") => {
                let m = f.next().unwrap_or("").trim();
                if !m.is_empty() && m != "none" {
                    inv.manager = Some(m.to_string());
                }
            }
            Some("PKG") => {
                let name = f.next().unwrap_or("").trim();
                let version = f.next().unwrap_or("").trim();
                if !name.is_empty() {
                    inv.packages.push(Package { name: name.to_string(), version: version.to_string() });
                }
            }
            _ => {}
        }
    }
    inv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_debian_style_inventory() {
        let out = "OS\tUbuntu 22.04.4 LTS\n\
                   MGR\tdpkg\n\
                   PKG\topenssh-server\t1:8.9p1-3ubuntu0.10\n\
                   PKG\tnginx\t1.18.0-6ubuntu14.4\n";
        let inv = parse_inventory(out);
        assert_eq!(inv.os.as_deref(), Some("Ubuntu 22.04.4 LTS"));
        assert_eq!(inv.manager.as_deref(), Some("dpkg"));
        assert_eq!(inv.packages.len(), 2);
        assert_eq!(inv.packages[0], Package { name: "openssh-server".into(), version: "1:8.9p1-3ubuntu0.10".into() });
        assert_eq!(inv.packages[1].name, "nginx");
    }

    #[test]
    fn parses_rpm_style_and_tolerates_blank_version() {
        let out = "OS\tFedora Linux 39\nMGR\trpm\nPKG\topenssh\t9.3p1-9.fc39\nPKG\tbusybox-1.36.1-r5\t\n";
        let inv = parse_inventory(out);
        assert_eq!(inv.manager.as_deref(), Some("rpm"));
        assert_eq!(inv.packages.len(), 2);
        assert_eq!(inv.packages[1].name, "busybox-1.36.1-r5");
        assert_eq!(inv.packages[1].version, "", "apk-style glued token keeps an empty version");
    }

    #[test]
    fn unknown_os_and_no_manager_are_none() {
        let inv = parse_inventory("OS\tunknown \nMGR\tnone\n");
        assert!(inv.os.is_none());
        assert!(inv.manager.is_none());
        assert!(inv.packages.is_empty());
    }

    #[test]
    fn ignores_unrelated_lines() {
        // A login banner or stray output before our markers must not break parsing.
        let inv = parse_inventory("Welcome to host\nLast login: ...\nOS\tDebian 12\nMGR\tdpkg\nPKG\tbash\t5.2\n");
        assert_eq!(inv.os.as_deref(), Some("Debian 12"));
        assert_eq!(inv.packages.len(), 1);
    }
}
