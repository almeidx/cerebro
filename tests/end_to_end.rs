//! End-to-end test of the gather → parse → audit pipeline with a mocked SSH runner.
//! Exercises every backend parser and the engine wiring without touching a real host.

use std::collections::BTreeMap;

use cerebro::config::{HostConfig, Settings};
use cerebro::engine::inventory::gather_host;
use cerebro::model::{HostHealth, InterfaceRole, Severity};
use cerebro::ssh::{ok_output, MockRunner};

fn sample_host() -> HostConfig {
    let mut interfaces = BTreeMap::new();
    interfaces.insert("eth0".to_string(), InterfaceRole::Public);
    interfaces.insert("tailscale0".to_string(), InterfaceRole::Tailnet);
    HostConfig {
        name: "web".to_string(),
        address: "web.tailnet.ts.net".to_string(),
        user: "root".to_string(),
        port: 22,
        groups: vec!["prod".to_string()],
        interfaces,
    }
}

#[tokio::test]
async fn gather_assembles_full_view_and_audit() {
    let runner = MockRunner::new()
        .on("uname", ok_output("6.12.0-55.el10\n"))
        .on(
            "/etc/os-release",
            ok_output("ID=rocky\nVERSION_ID=\"10\"\nPRETTY_NAME=\"Rocky Linux 10\"\n"),
        )
        .on("getenforce", ok_output("Enforcing\n"))
        .on("/proc/uptime", ok_output("123456.78 100000.00\n"))
        .on(
            "--list-all-zones",
            ok_output("public (active)\n  interfaces: eth0\n  services: ssh\n  ports: 80/tcp\n  rich rules:\n"),
        )
        .on(
            "-tulpn",
            ok_output(
                "tcp LISTEN 0 128 0.0.0.0:5432 0.0.0.0:* users:((\"postgres\",pid=1,fd=3))\n",
            ),
        )
        .on(
            "docker ps",
            ok_output(
                "{\"ID\":\"a1\",\"Image\":\"nginx:1.27\",\"Names\":\"web\",\"State\":\"running\",\"Status\":\"Up 2 days\",\"Ports\":\"0.0.0.0:8080->80/tcp\",\"Labels\":\"com.docker.compose.project=app\"}\n",
            ),
        )
        .on("crontab -l", ok_output("*/5 * * * * /usr/bin/check.sh\n"))
        .on("/etc/crontab", ok_output("0 3 * * * root /sbin/logrotate\n"))
        .on("check-update", ok_output("curl.x86_64 8.9.1-5.el10_0 baseos\n"))
        .on(
            "updateinfo",
            ok_output("RLSA-2024:1 Critical/Sec. curl-8.9.1-5.el10_0.x86_64\n"),
        )
        .on(
            "tailscale status",
            ok_output("{\"BackendState\":\"Running\",\"Self\":{\"HostName\":\"web\",\"Online\":true}}"),
        )
        .fallback(ok_output(""));

    let view = gather_host(&runner, &sample_host(), &Settings::default()).await;

    assert_eq!(view.health, HostHealth::Online);
    let facts = view.facts.as_ref().expect("facts gathered");
    assert_eq!(facts.kernel, "6.12.0-55.el10");
    assert_eq!(facts.os.distro, cerebro::model::Distro::Rocky);

    assert_eq!(view.containers.len(), 1);
    assert!(view.containers[0].is_publicly_exposed());
    assert!(view.sockets.iter().any(|s| s.local_port == 5432));
    assert!(!view.cron.is_empty());
    assert_eq!(view.security_update_count(), 1);
    assert!(view.tailscale.as_ref().is_some_and(|t| t.online));

    let audit = view.audit.expect("audit produced");
    assert_eq!(audit.max_severity(), Severity::Critical);
    assert!(audit.findings.iter().any(|f| f.id.contains("5432")));
}

#[tokio::test]
async fn unreachable_host_is_marked_not_crashed() {
    // The real ssh client maps a transport failure (exit 255) to Error::Ssh; model that
    // with a runner that errors, so the probe degrades the host rather than panicking.
    struct DownRunner;
    #[async_trait::async_trait]
    impl cerebro::ssh::CommandRunner for DownRunner {
        async fn run(
            &self,
            target: &cerebro::ssh::SshTarget,
            _argv: &[&str],
        ) -> cerebro::Result<cerebro::ssh::CmdOutput> {
            Err(cerebro::Error::Ssh {
                host: target.host.clone(),
                message: "connect to host web port 22: Connection refused".to_string(),
            })
        }
    }
    let view = gather_host(&DownRunner, &sample_host(), &Settings::default()).await;
    assert_eq!(view.health, HostHealth::Unreachable);
    assert!(view.facts.is_none());
}
