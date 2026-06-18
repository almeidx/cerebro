//! Agentless command execution over SSH.
//!
//! Cerebro shells out to the system OpenSSH client so it transparently inherits the
//! operator's `~/.ssh/config`, `known_hosts`, ssh-agent and — crucially — Tailscale SSH
//! identity auth. Execution sits behind the [`CommandRunner`] trait so the engine can be
//! exercised in tests with [`MockRunner`].

use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use tokio::process::Command;

use crate::error::{Error, Result};

/// Where and how to reach a single host.
#[derive(Debug, Clone)]
pub struct SshTarget {
    /// Logical name from `cerebro.toml` (used in diagnostics).
    pub host: String,
    /// Address ssh actually connects to (tailnet hostname or IP).
    pub address: String,
    pub user: String,
    pub port: u16,
    pub connect_timeout: Duration,
    /// Optional ControlMaster socket path enabling connection multiplexing.
    pub control_path: Option<String>,
}

impl SshTarget {
    pub fn new(host: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            address: address.into(),
            user: "root".to_string(),
            port: 22,
            connect_timeout: Duration::from_secs(8),
            control_path: None,
        }
    }
}

/// Captured result of a single remote command.
#[derive(Debug, Clone)]
pub struct CmdOutput {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    pub fn success(&self) -> bool {
        self.status == 0
    }

    /// Return stdout if the command succeeded, otherwise a [`Error::RemoteCommand`].
    pub fn stdout_checked(self, host: &str) -> Result<String> {
        if self.success() {
            Ok(self.stdout)
        } else {
            Err(Error::RemoteCommand {
                host: host.to_string(),
                code: self.status,
                stderr: self.stderr,
            })
        }
    }
}

/// Abstraction over "run an argv on a remote host".
#[async_trait]
pub trait CommandRunner: Send + Sync {
    async fn run(&self, target: &SshTarget, remote_argv: &[&str]) -> Result<CmdOutput>;
}

/// POSIX single-quote escape one argument for safe inclusion in a remote shell line.
pub fn posix_quote(arg: &str) -> String {
    let safe = !arg.is_empty()
        && arg.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'_' | b'-' | b'.' | b'/' | b':' | b'=' | b'@' | b',' | b'+'
                )
        });
    if safe {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for c in arg.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Quote and join a remote argv into a single shell-safe command line.
pub fn join_remote(remote_argv: &[&str]) -> String {
    remote_argv
        .iter()
        .map(|a| posix_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Whether an SSH failure looks like a Tailscale re-authentication prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReauthOutcome {
    NotReauth,
    Reauth { auth_url: Option<String> },
}

/// Inspect stderr from a failed connection for the Tailscale re-auth signature.
pub fn detect_reauth(stderr: &str) -> ReauthOutcome {
    let lower = stderr.to_lowercase();
    let is_reauth = lower.contains("to authenticate, visit")
        || lower.contains("reauthenticate")
        || lower.contains("re-authenticate")
        || lower.contains("needslogin")
        || (lower.contains("tailscale")
            && (lower.contains("login")
                || lower.contains("authoriz")
                || lower.contains("authenticat")));
    if !is_reauth {
        return ReauthOutcome::NotReauth;
    }
    let auth_url = stderr
        .split_whitespace()
        .find(|t| t.starts_with("https://"))
        .map(|t| t.trim_end_matches(['.', ',', ')']).to_string())
        .filter(|u| u.starts_with("https://") && !u.contains(['"', '\'', '<', '>']));
    ReauthOutcome::Reauth { auth_url }
}

/// Build the argv passed to the local `ssh` binary.
fn build_ssh_args(target: &SshTarget, remote_line: &str) -> Vec<String> {
    let mut args = vec![
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        format!("ConnectTimeout={}", target.connect_timeout.as_secs().max(1)),
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
    ];
    if let Some(cp) = &target.control_path {
        args.push("-o".to_string());
        args.push("ControlMaster=auto".to_string());
        args.push("-o".to_string());
        args.push(format!("ControlPath={cp}"));
        args.push("-o".to_string());
        args.push("ControlPersist=60".to_string());
    }
    args.push("-p".to_string());
    args.push(target.port.to_string());
    args.push(format!("{}@{}", target.user, target.address));
    args.push("--".to_string());
    args.push(remote_line.to_string());
    args
}

/// Real runner that invokes the system `ssh` client.
pub struct SshRunner {
    ssh_path: String,
}

impl Default for SshRunner {
    fn default() -> Self {
        Self {
            ssh_path: "ssh".to_string(),
        }
    }
}

impl SshRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_ssh_path(ssh_path: impl Into<String>) -> Self {
        Self {
            ssh_path: ssh_path.into(),
        }
    }
}

#[async_trait]
impl CommandRunner for SshRunner {
    async fn run(&self, target: &SshTarget, remote_argv: &[&str]) -> Result<CmdOutput> {
        let remote_line = join_remote(remote_argv);
        let args = build_ssh_args(target, &remote_line);
        let output = Command::new(&self.ssh_path)
            .args(&args)
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|e| Error::Ssh {
                host: target.host.clone(),
                message: e.to_string(),
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let status = output.status.code().unwrap_or(-1);

        if !output.status.success() {
            if let ReauthOutcome::Reauth { auth_url } = detect_reauth(&stderr) {
                return Err(Error::NeedsReauth {
                    host: target.host.clone(),
                    auth_url,
                });
            }
            // 255 is the ssh client's own "transport failed" exit code.
            if status == 255 {
                return Err(Error::Ssh {
                    host: target.host.clone(),
                    message: stderr.trim().to_string(),
                });
            }
        }

        Ok(CmdOutput {
            status,
            stdout,
            stderr,
        })
    }
}

/// Test double: matches remote command lines against substrings.
#[derive(Default)]
pub struct MockRunner {
    rules: Vec<(String, CmdOutput)>,
    fallback: Option<CmdOutput>,
}

impl MockRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reply with `out` whenever the joined remote argv contains `needle`.
    #[must_use]
    pub fn on(mut self, needle: &str, out: CmdOutput) -> Self {
        self.rules.push((needle.to_string(), out));
        self
    }

    /// Reply with `out` for any command that matches no rule.
    #[must_use]
    pub fn fallback(mut self, out: CmdOutput) -> Self {
        self.fallback = Some(out);
        self
    }
}

#[async_trait]
impl CommandRunner for MockRunner {
    async fn run(&self, _target: &SshTarget, remote_argv: &[&str]) -> Result<CmdOutput> {
        let joined = remote_argv.join(" ");
        for (needle, out) in &self.rules {
            if joined.contains(needle) {
                return Ok(out.clone());
            }
        }
        match &self.fallback {
            Some(out) => Ok(out.clone()),
            None => Ok(CmdOutput {
                status: 127,
                stdout: String::new(),
                stderr: format!("MockRunner: no rule for `{joined}`"),
            }),
        }
    }
}

/// Helper for building a successful [`CmdOutput`] in tests/seed data.
pub fn ok_output(stdout: impl Into<String>) -> CmdOutput {
    CmdOutput {
        status: 0,
        stdout: stdout.into(),
        stderr: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_plain_arg_unchanged() {
        assert_eq!(posix_quote("firewall-cmd"), "firewall-cmd");
        assert_eq!(posix_quote("--list-all"), "--list-all");
        assert_eq!(posix_quote("8443/tcp"), "8443/tcp");
    }

    #[test]
    fn quotes_dangerous_arg() {
        assert_eq!(posix_quote("a b"), "'a b'");
        assert_eq!(posix_quote("$(rm -rf /)"), "'$(rm -rf /)'");
        assert_eq!(posix_quote("it's"), "'it'\\''s'");
        assert_eq!(posix_quote(""), "''");
    }

    #[test]
    fn joins_remote_argv_safely() {
        let line = join_remote(&["sh", "-c", "echo hi; rm x"]);
        assert_eq!(line, "sh -c 'echo hi; rm x'");
    }

    #[test]
    fn detects_tailscale_reauth_with_url() {
        let stderr = "Tailscale SSH requires re-authentication.\nTo authenticate, visit:\n\thttps://login.tailscale.com/a/abc123\n";
        match detect_reauth(stderr) {
            ReauthOutcome::Reauth { auth_url } => {
                assert_eq!(
                    auth_url.as_deref(),
                    Some("https://login.tailscale.com/a/abc123")
                );
            }
            ReauthOutcome::NotReauth => panic!("expected reauth"),
        }
    }

    #[test]
    fn ignores_ordinary_connection_errors() {
        assert_eq!(
            detect_reauth("ssh: connect to host x port 22: Connection refused"),
            ReauthOutcome::NotReauth
        );
    }

    #[test]
    fn detects_reauth_without_a_url() {
        // Tailscale can require re-auth without printing a clickable link.
        assert_eq!(
            detect_reauth("Tailscale: you need to reauthenticate to access this host"),
            ReauthOutcome::Reauth { auth_url: None }
        );
    }

    #[test]
    fn rejects_non_https_auth_url() {
        // A non-https token must never be surfaced as a clickable auth link.
        assert_eq!(
            detect_reauth("tailscale login required: http://evil.example/login"),
            ReauthOutcome::Reauth { auth_url: None }
        );
    }

    #[test]
    fn ssh_args_include_multiplexing_when_control_path_set() {
        let mut target = SshTarget::new("web", "web.tailnet.ts.net");
        target.control_path = Some("/tmp/cerebro-web.sock".to_string());
        let args = build_ssh_args(&target, "uname -r");
        assert!(args.iter().any(|a| a == "ControlMaster=auto"));
        assert!(args
            .iter()
            .any(|a| a == "ControlPath=/tmp/cerebro-web.sock"));
        assert!(args.iter().any(|a| a == "root@web.tailnet.ts.net"));
        assert_eq!(args.last().unwrap(), "uname -r");
    }

    #[tokio::test]
    async fn mock_runner_matches_rules() {
        let runner = MockRunner::new()
            .on("uname", ok_output("6.1.0"))
            .fallback(ok_output("default"));
        let target = SshTarget::new("h", "h");
        let out = runner.run(&target, &["uname", "-r"]).await.unwrap();
        assert_eq!(out.stdout, "6.1.0");
        let other = runner.run(&target, &["whoami"]).await.unwrap();
        assert_eq!(other.stdout, "default");
    }
}
