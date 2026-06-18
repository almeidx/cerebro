//! Live, agentless gathering of per-host state via the SSH runner.
//!
//! Each call fans a handful of read-only commands at a host, feeds their output through
//! the pure [`crate::backends`] parsers, and assembles a [`HostView`]. Connection or
//! Tailscale-reauth failures degrade the single host without affecting the rest of the
//! fleet.

use std::sync::Arc;

use chrono::Utc;

use crate::backends::{cron, dnf, docker, firewalld, os_release, sockets, tailscale};
use crate::config::{Config, HostConfig, Settings};
use crate::engine::audit::{self, AuditInputs};
use crate::error::Error;
use crate::model::{Facts, HostHealth, HostView, NetInterface, SelinuxMode};
use crate::ssh::{CommandRunner, SshTarget};

async fn run_ok(runner: &dyn CommandRunner, target: &SshTarget, argv: &[&str]) -> Option<String> {
    match runner.run(target, argv).await {
        Ok(out) if out.success() => Some(out.stdout),
        _ => None,
    }
}

/// Like [`run_ok`] but also accepts the listed non-zero exit codes (e.g. `dnf
/// check-update` returns 100 when updates are pending).
async fn run_allowing(
    runner: &dyn CommandRunner,
    target: &SshTarget,
    argv: &[&str],
    allowed: &[i32],
) -> Option<String> {
    match runner.run(target, argv).await {
        Ok(out) if out.success() || allowed.contains(&out.status) => Some(out.stdout),
        _ => None,
    }
}

fn selinux_from(raw: &str) -> SelinuxMode {
    match raw.trim() {
        "Enforcing" => SelinuxMode::Enforcing,
        "Permissive" => SelinuxMode::Permissive,
        "Disabled" => SelinuxMode::Disabled,
        _ => SelinuxMode::Unknown,
    }
}

fn uptime_from(raw: &str) -> Option<u64> {
    raw.split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()
        .map(|secs| secs as u64)
}

fn interfaces_from(host: &HostConfig) -> Vec<NetInterface> {
    host.interfaces
        .iter()
        .map(|(name, role)| NetInterface {
            name: name.clone(),
            role: *role,
            addresses: Vec::new(),
        })
        .collect()
}

/// Gather everything Cerebro knows how to read from a single host.
pub async fn gather_host(
    runner: &dyn CommandRunner,
    host: &HostConfig,
    settings: &Settings,
) -> HostView {
    let mut view = HostView::new(host.name.clone(), host.groups.clone());
    let target = host.ssh_target(settings);

    // Connectivity probe. A successful SSH *transport* means the host is reachable even
    // if the probe command itself exits non-zero; only a transport error (or a Tailscale
    // re-auth signal) degrades the host.
    let kernel = match runner.run(&target, &["uname", "-r"]).await {
        Ok(out) => {
            view.health = HostHealth::Online;
            if out.success() {
                out.stdout.trim().to_string()
            } else {
                String::new()
            }
        }
        Err(Error::NeedsReauth { auth_url, .. }) => {
            view.health = HostHealth::NeedsReauth;
            view.auth_url = auth_url;
            view.last_polled = Some(Utc::now());
            return view;
        }
        Err(e) => {
            view.health = HostHealth::Unreachable;
            view.error = Some(e.to_string());
            view.last_polled = Some(Utc::now());
            return view;
        }
    };

    if let Some(os_raw) = run_ok(runner, &target, &["cat", "/etc/os-release"]).await {
        let os = os_release::parse(&os_raw);
        let selinux = run_ok(runner, &target, &["getenforce"])
            .await
            .map(|s| selinux_from(&s))
            .unwrap_or_default();
        let uptime_secs = run_ok(runner, &target, &["cat", "/proc/uptime"])
            .await
            .and_then(|s| uptime_from(&s));
        view.facts = Some(Facts {
            os,
            kernel,
            selinux,
            uptime_secs,
            interfaces: interfaces_from(host),
        });
    }

    if let Some(raw) = run_ok(runner, &target, &["firewall-cmd", "--list-all-zones"]).await {
        view.firewall = Some(firewalld::parse_list_all_zones(&raw));
    }
    if let Some(raw) = run_ok(runner, &target, &["ss", "-H", "-tulpn"]).await {
        view.sockets = sockets::parse_ss(&raw);
    }
    if let Some(raw) = run_ok(
        runner,
        &target,
        &["docker", "ps", "-a", "--format", "{{json .}}"],
    )
    .await
    {
        if let Ok(containers) = docker::parse_ps(&raw) {
            view.containers = containers;
        }
    }

    let mut jobs = Vec::new();
    if let Some(raw) = run_ok(runner, &target, &["crontab", "-l"]).await {
        jobs.extend(cron::parse_user_crontab("root", &raw));
    }
    if let Some(raw) = run_ok(runner, &target, &["cat", "/etc/crontab"]).await {
        jobs.extend(cron::parse_etc_crontab(&raw));
    }
    view.cron = jobs;

    let check = run_allowing(runner, &target, &["dnf", "--quiet", "check-update"], &[100])
        .await
        .unwrap_or_default();
    if !check.trim().is_empty() {
        let info = run_ok(
            runner,
            &target,
            &["dnf", "--quiet", "updateinfo", "list", "--available"],
        )
        .await
        .unwrap_or_default();
        view.updates = dnf::parse(&check, &info);
    }

    if let Some(raw) = run_ok(runner, &target, &["tailscale", "status", "--json"]).await {
        if let Ok(status) = tailscale::parse_status(&raw) {
            view.tailscale = Some(status);
        }
    }

    let inputs = AuditInputs {
        facts: view.facts.as_ref(),
        firewall: view.firewall.as_ref(),
        sockets: &view.sockets,
        containers: &view.containers,
        updates: &view.updates,
        sshd: None,
    };
    view.audit = Some(audit::audit_host(&host.name, &inputs));
    view.last_polled = Some(Utc::now());
    view
}

/// Gather every host in the inventory concurrently.
pub async fn gather_fleet(runner: Arc<dyn CommandRunner>, config: &Config) -> Vec<HostView> {
    let mut handles = Vec::with_capacity(config.hosts.len());
    for host in &config.hosts {
        let runner = Arc::clone(&runner);
        let name = host.name.clone();
        let groups = host.groups.clone();
        let host = host.clone();
        let settings = config.settings.clone();
        let handle =
            tokio::spawn(async move { gather_host(runner.as_ref(), &host, &settings).await });
        handles.push((name, groups, handle));
    }
    let mut views = Vec::with_capacity(handles.len());
    for (name, groups, handle) in handles {
        if let Ok(view) = handle.await {
            views.push(view);
        } else {
            // A panic in one gather task must not erase the host from the fleet.
            let mut view = HostView::new(name, groups);
            view.health = HostHealth::Unreachable;
            view.error = Some("internal gather task failed".to_string());
            views.push(view);
        }
    }
    views
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::{ok_output, MockRunner};

    fn host() -> HostConfig {
        HostConfig {
            name: "web".to_string(),
            address: "web.tailnet.ts.net".to_string(),
            user: "root".to_string(),
            port: 22,
            groups: vec!["prod".to_string()],
            interfaces: std::collections::BTreeMap::new(),
        }
    }

    #[tokio::test]
    async fn online_host_is_gathered() {
        let runner = MockRunner::new()
            .on("uname", ok_output("6.12.0-55.el10\n"))
            .on("os-release", ok_output("ID=rocky\nVERSION_ID=\"10\"\n"))
            .on("getenforce", ok_output("Enforcing\n"))
            .fallback(ok_output(""));
        let view = gather_host(&runner, &host(), &Settings::default()).await;
        assert_eq!(view.health, HostHealth::Online);
        assert!(view.facts.is_some());
        assert_eq!(view.facts.unwrap().kernel, "6.12.0-55.el10");
    }

    #[tokio::test]
    async fn reauth_degrades_single_host() {
        struct ReauthRunner;
        #[async_trait::async_trait]
        impl CommandRunner for ReauthRunner {
            async fn run(
                &self,
                target: &SshTarget,
                _argv: &[&str],
            ) -> crate::error::Result<crate::ssh::CmdOutput> {
                Err(Error::NeedsReauth {
                    host: target.host.clone(),
                    auth_url: Some("https://login.tailscale.com/a/x".to_string()),
                })
            }
        }
        let view = gather_host(&ReauthRunner, &host(), &Settings::default()).await;
        assert_eq!(view.health, HostHealth::NeedsReauth);
        assert_eq!(
            view.auth_url.as_deref(),
            Some("https://login.tailscale.com/a/x")
        );
    }
}
