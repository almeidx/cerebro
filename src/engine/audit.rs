//! External-exposure security audit.
//!
//! Given the read-only facts Cerebro has gathered about a single host, produce an
//! [`AuditReport`]: a list of [`Finding`]s each carrying a stable id slug, a severity
//! and an operator-facing recommendation. The audit is a pure function of its inputs so
//! it can be exercised exhaustively in tests without any SSH or I/O.

use crate::model::{
    AuditReport, Container, Facts, Finding, FindingCategory, FirewallState, ListeningSocket,
    OsUpdate, SelinuxMode, Severity, SshdConfig,
};

/// Ports that, when exposed on a wildcard address, warrant an elevated severity because
/// they front a database that should almost never be internet-reachable.
const DATABASE_PORTS: &[u16] = &[5432, 3306, 6379, 27017, 5984];

/// The TCP port for SSH, exempt from the generic exposure check since remote management
/// is the whole point of the tool.
const SSH_PORT: u16 = 22;

/// Everything the audit needs to know about one host.
pub struct AuditInputs<'a> {
    pub facts: Option<&'a Facts>,
    pub firewall: Option<&'a FirewallState>,
    pub sockets: &'a [ListeningSocket],
    pub containers: &'a [Container],
    pub updates: &'a [OsUpdate],
    pub sshd: Option<&'a SshdConfig>,
}

/// Run every audit check against `inputs` and collect the findings for `host`.
pub fn audit_host(host: &str, inputs: &AuditInputs) -> AuditReport {
    let mut findings = Vec::new();

    audit_exposure(inputs.sockets, &mut findings);
    audit_ssh(inputs.sshd, &mut findings);
    audit_selinux(inputs.facts, &mut findings);
    audit_errata(inputs.updates, &mut findings);
    audit_docker(inputs.containers, &mut findings);

    AuditReport {
        host: host.to_string(),
        findings,
    }
}

fn audit_exposure(sockets: &[ListeningSocket], findings: &mut Vec<Finding>) {
    for socket in sockets {
        if !socket.is_wildcard() || socket.local_port == SSH_PORT {
            continue;
        }
        let port = socket.local_port;
        let is_database = DATABASE_PORTS.contains(&port);
        let severity = if is_database {
            Severity::Important
        } else {
            Severity::Moderate
        };
        let process = socket.process.as_deref().unwrap_or("unknown process");
        // Fold protocol and IP family into the id so a dual-stack (0.0.0.0 + [::]) or
        // tcp+udp pair on the same port produces distinct, stable findings.
        let family = if socket.local_addr.contains(':') {
            "v6"
        } else {
            "v4"
        };
        let detail = format!(
            "{} port {port} ({process}) is listening on wildcard address {}",
            socket.protocol, socket.local_addr
        );
        let recommendation = if is_database {
            Some(format!(
                "Bind {process} to a private/tailnet address or restrict port {port} with the firewall"
            ))
        } else {
            Some(format!(
                "Confirm port {port} is meant to be internet-facing; otherwise bind it to a private address"
            ))
        };
        findings.push(Finding {
            id: format!("exposure.{}.{family}.{port}", socket.protocol),
            title: format!("Port {port} exposed on all interfaces"),
            severity,
            category: FindingCategory::Exposure,
            detail,
            recommendation,
        });
    }
}

fn audit_ssh(sshd: Option<&SshdConfig>, findings: &mut Vec<Finding>) {
    let Some(sshd) = sshd else {
        return;
    };

    if sshd.permit_root_login.as_deref() == Some("yes") {
        findings.push(Finding {
            id: "ssh.root_login".to_string(),
            title: "SSH permits direct root login".to_string(),
            severity: Severity::Important,
            category: FindingCategory::Ssh,
            detail: "sshd_config sets PermitRootLogin yes".to_string(),
            recommendation: Some(
                "Set PermitRootLogin to prohibit-password or no and use an unprivileged account"
                    .to_string(),
            ),
        });
    }

    if sshd.password_authentication == Some(true) {
        findings.push(Finding {
            id: "ssh.password_auth".to_string(),
            title: "SSH allows password authentication".to_string(),
            severity: Severity::Moderate,
            category: FindingCategory::Ssh,
            detail: "sshd_config sets PasswordAuthentication yes".to_string(),
            recommendation: Some(
                "Disable PasswordAuthentication and rely on public-key authentication".to_string(),
            ),
        });
    }
}

fn audit_selinux(facts: Option<&Facts>, findings: &mut Vec<Finding>) {
    let Some(facts) = facts else {
        return;
    };

    match facts.selinux {
        SelinuxMode::Permissive => findings.push(Finding {
            id: "selinux.permissive".to_string(),
            title: "SELinux is in permissive mode".to_string(),
            severity: Severity::Low,
            category: FindingCategory::Selinux,
            detail: "SELinux logs denials but does not enforce its policy".to_string(),
            recommendation: Some(
                "Switch SELinux to enforcing once you have confirmed there are no blocking denials"
                    .to_string(),
            ),
        }),
        SelinuxMode::Disabled => findings.push(Finding {
            id: "selinux.disabled".to_string(),
            title: "SELinux is disabled".to_string(),
            severity: Severity::Important,
            category: FindingCategory::Selinux,
            detail: "SELinux provides no mandatory access control on this host".to_string(),
            recommendation: Some(
                "Re-enable SELinux in enforcing mode (a relabel and reboot may be required)"
                    .to_string(),
            ),
        }),
        SelinuxMode::Enforcing | SelinuxMode::Unknown => {}
    }
}

fn audit_errata(updates: &[OsUpdate], findings: &mut Vec<Finding>) {
    let security: Vec<&OsUpdate> = updates.iter().filter(|u| u.is_security()).collect();
    let n = security.len();
    if n == 0 {
        return;
    }

    let severity = Severity::max_of(
        security
            .iter()
            .filter_map(|u| u.errata.as_ref())
            .map(|e| e.severity),
    );
    let severity = if severity == Severity::Unknown {
        Severity::Moderate
    } else {
        severity
    };

    findings.push(Finding {
        id: "errata.security".to_string(),
        title: format!("{n} pending security updates"),
        severity,
        category: FindingCategory::Errata,
        detail: format!("{n} package update(s) carry a security errata advisory"),
        recommendation: Some(
            "Apply the pending security updates and reboot if the kernel was updated".to_string(),
        ),
    });
}

fn audit_docker(containers: &[Container], findings: &mut Vec<Finding>) {
    for container in containers {
        if !container.is_publicly_exposed() {
            continue;
        }
        let name = &container.name;
        findings.push(Finding {
            id: format!("docker.exposed.{name}"),
            title: format!("Container {name} publishes a port on all interfaces"),
            severity: Severity::Moderate,
            category: FindingCategory::Docker,
            detail: format!(
                "Container {name} (image {}) binds a host port on a wildcard address",
                container.image
            ),
            recommendation: Some(format!(
                "Publish {name}'s ports to a specific private address (e.g. 127.0.0.1) or front it with a reverse proxy"
            )),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        Distro, Errata, ErrataKind, NetInterface, OsRelease, PortMapping, Protocol,
    };

    fn enforcing_facts() -> Facts {
        Facts {
            os: OsRelease {
                id: "rocky".to_string(),
                version_id: Some("10.0".to_string()),
                pretty_name: Some("Rocky Linux 10.0 (Red Quartz)".to_string()),
                distro: Distro::Rocky,
            },
            kernel: "6.12.0-55.el10.x86_64".to_string(),
            selinux: SelinuxMode::Enforcing,
            uptime_secs: Some(86_400),
            interfaces: vec![NetInterface {
                name: "eth0".to_string(),
                role: crate::model::InterfaceRole::Public,
                addresses: vec!["203.0.113.10".to_string()],
            }],
        }
    }

    fn facts_with_selinux(mode: SelinuxMode) -> Facts {
        Facts {
            selinux: mode,
            ..enforcing_facts()
        }
    }

    fn wildcard_socket(port: u16, process: &str) -> ListeningSocket {
        ListeningSocket {
            protocol: Protocol::Tcp,
            local_addr: "0.0.0.0".to_string(),
            local_port: port,
            process: Some(process.to_string()),
            pid: Some(4242),
        }
    }

    fn loopback_socket(port: u16, process: &str) -> ListeningSocket {
        ListeningSocket {
            protocol: Protocol::Tcp,
            local_addr: "127.0.0.1".to_string(),
            local_port: port,
            process: Some(process.to_string()),
            pid: Some(4242),
        }
    }

    fn security_update(name: &str, advisory: &str, severity: Severity) -> OsUpdate {
        OsUpdate {
            name: name.to_string(),
            arch: Some("x86_64".to_string()),
            current_version: Some("1.0.0".to_string()),
            new_version: "1.0.1".to_string(),
            repo: Some("baseos".to_string()),
            errata: Some(Errata {
                advisory: advisory.to_string(),
                severity,
                kind: ErrataKind::Security,
            }),
        }
    }

    fn exposed_container(name: &str) -> Container {
        Container {
            id: "deadbeefcafe".to_string(),
            name: name.to_string(),
            image: "nginx:latest".to_string(),
            image_digest: None,
            state: "running".to_string(),
            status: "Up 3 days".to_string(),
            ports: vec![PortMapping {
                host_ip: Some("0.0.0.0".to_string()),
                host_port: Some("8080".to_string()),
                container_port: "80".to_string(),
                protocol: Protocol::Tcp,
            }],
            restart_policy: Some("unless-stopped".to_string()),
            health: None,
            compose_project: Some("stack".to_string()),
        }
    }

    fn hardened_sshd() -> SshdConfig {
        SshdConfig {
            permit_root_login: Some("no".to_string()),
            password_authentication: Some(false),
            pubkey_authentication: Some(true),
            port: Some(22),
        }
    }

    fn find<'a>(report: &'a AuditReport, id: &str) -> &'a Finding {
        report
            .findings
            .iter()
            .find(|f| f.id == id)
            .unwrap_or_else(|| panic!("expected finding {id}, got {:?}", report.findings))
    }

    #[test]
    fn flags_every_category_at_expected_severity() {
        let facts = facts_with_selinux(SelinuxMode::Disabled);
        let firewall = None;
        let sockets = vec![wildcard_socket(5432, "postgres")];
        let containers = vec![exposed_container("web")];
        let updates = vec![
            security_update("kernel", "RLSA-2026:0001", Severity::Critical),
            security_update("openssl", "RLSA-2026:0002", Severity::Important),
        ];
        let sshd = SshdConfig {
            permit_root_login: Some("yes".to_string()),
            password_authentication: Some(true),
            pubkey_authentication: Some(true),
            port: Some(22),
        };

        let inputs = AuditInputs {
            facts: Some(&facts),
            firewall,
            sockets: &sockets,
            containers: &containers,
            updates: &updates,
            sshd: Some(&sshd),
        };

        let report = audit_host("db-01", &inputs);
        assert_eq!(report.host, "db-01");

        let exposure = find(&report, "exposure.tcp.v4.5432");
        assert_eq!(exposure.severity, Severity::Important);
        assert_eq!(exposure.category, FindingCategory::Exposure);
        assert!(exposure.detail.contains("postgres"));
        assert!(exposure.detail.contains("5432"));

        let root_login = find(&report, "ssh.root_login");
        assert_eq!(root_login.severity, Severity::Important);
        assert_eq!(root_login.category, FindingCategory::Ssh);

        let password_auth = find(&report, "ssh.password_auth");
        assert_eq!(password_auth.severity, Severity::Moderate);

        let selinux = find(&report, "selinux.disabled");
        assert_eq!(selinux.severity, Severity::Important);
        assert_eq!(selinux.category, FindingCategory::Selinux);

        let errata = find(&report, "errata.security");
        assert_eq!(errata.severity, Severity::Critical);
        assert_eq!(errata.category, FindingCategory::Errata);
        assert_eq!(errata.title, "2 pending security updates");

        let docker = find(&report, "docker.exposed.web");
        assert_eq!(docker.severity, Severity::Moderate);
        assert_eq!(docker.category, FindingCategory::Docker);
        assert!(docker.detail.contains("web"));

        assert_eq!(report.max_severity(), Severity::Critical);
    }

    #[test]
    fn clean_host_yields_no_findings() {
        let facts = facts_with_selinux(SelinuxMode::Enforcing);
        let sockets = vec![
            loopback_socket(5432, "postgres"),
            wildcard_socket(22, "sshd"),
        ];
        let containers: Vec<Container> = Vec::new();
        let updates = vec![OsUpdate {
            name: "vim".to_string(),
            arch: Some("x86_64".to_string()),
            current_version: Some("9.0".to_string()),
            new_version: "9.1".to_string(),
            repo: Some("appstream".to_string()),
            errata: Some(Errata {
                advisory: "RLBA-2026:0003".to_string(),
                severity: Severity::Low,
                kind: ErrataKind::BugFix,
            }),
        }];
        let sshd = hardened_sshd();

        let inputs = AuditInputs {
            facts: Some(&facts),
            firewall: None,
            sockets: &sockets,
            containers: &containers,
            updates: &updates,
            sshd: Some(&sshd),
        };

        let report = audit_host("clean-01", &inputs);
        assert!(
            report.findings.is_empty(),
            "expected no findings, got {:?}",
            report.findings
        );
        assert_eq!(report.max_severity(), Severity::Unknown);
    }

    #[test]
    fn ssh_on_wildcard_is_not_flagged_but_other_ports_are() {
        let sockets = vec![wildcard_socket(22, "sshd"), wildcard_socket(8080, "nginx")];
        let inputs = AuditInputs {
            facts: None,
            firewall: None,
            sockets: &sockets,
            containers: &[],
            updates: &[],
            sshd: None,
        };
        let report = audit_host("h", &inputs);
        assert!(report.findings.iter().all(|f| !f.id.ends_with(".22")));
        let web = find(&report, "exposure.tcp.v4.8080");
        assert_eq!(web.severity, Severity::Moderate);
    }

    #[test]
    fn dual_stack_exposure_yields_distinct_finding_ids() {
        let v6 = ListeningSocket {
            protocol: Protocol::Tcp,
            local_addr: "[::]".to_string(),
            local_port: 8080,
            process: Some("nginx".to_string()),
            pid: Some(7),
        };
        let sockets = vec![wildcard_socket(8080, "nginx"), v6];
        let inputs = AuditInputs {
            facts: None,
            firewall: None,
            sockets: &sockets,
            containers: &[],
            updates: &[],
            sshd: None,
        };
        let report = audit_host("h", &inputs);
        find(&report, "exposure.tcp.v4.8080");
        find(&report, "exposure.tcp.v6.8080");
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids.len(), 2, "expected two distinct findings, got {ids:?}");
    }

    #[test]
    fn permissive_selinux_is_low() {
        let facts = facts_with_selinux(SelinuxMode::Permissive);
        let inputs = AuditInputs {
            facts: Some(&facts),
            firewall: None,
            sockets: &[],
            containers: &[],
            updates: &[],
            sshd: None,
        };
        let report = audit_host("h", &inputs);
        let finding = find(&report, "selinux.permissive");
        assert_eq!(finding.severity, Severity::Low);
    }

    #[test]
    fn unknown_selinux_and_enforcing_are_silent() {
        for mode in [SelinuxMode::Enforcing, SelinuxMode::Unknown] {
            let facts = facts_with_selinux(mode);
            let inputs = AuditInputs {
                facts: Some(&facts),
                firewall: None,
                sockets: &[],
                containers: &[],
                updates: &[],
                sshd: None,
            };
            let report = audit_host("h", &inputs);
            assert!(report.findings.is_empty());
        }
    }

    #[test]
    fn security_errata_without_severity_falls_back_to_moderate() {
        let updates = vec![security_update("zlib", "RLSA-2026:0009", Severity::Unknown)];
        let inputs = AuditInputs {
            facts: None,
            firewall: None,
            sockets: &[],
            containers: &[],
            updates: &updates,
            sshd: None,
        };
        let report = audit_host("h", &inputs);
        let errata = find(&report, "errata.security");
        assert_eq!(errata.severity, Severity::Moderate);
        assert_eq!(errata.title, "1 pending security updates");
    }

    #[test]
    fn root_login_prohibit_password_is_not_flagged() {
        let sshd = SshdConfig {
            permit_root_login: Some("prohibit-password".to_string()),
            password_authentication: Some(false),
            pubkey_authentication: Some(true),
            port: Some(22),
        };
        let inputs = AuditInputs {
            facts: None,
            firewall: None,
            sockets: &[],
            containers: &[],
            updates: &[],
            sshd: Some(&sshd),
        };
        let report = audit_host("h", &inputs);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn non_security_updates_produce_no_errata_finding() {
        let updates = vec![OsUpdate {
            name: "bash".to_string(),
            arch: None,
            current_version: None,
            new_version: "5.2".to_string(),
            repo: None,
            errata: None,
        }];
        let inputs = AuditInputs {
            facts: None,
            firewall: None,
            sockets: &[],
            containers: &[],
            updates: &updates,
            sshd: None,
        };
        let report = audit_host("h", &inputs);
        assert!(report.findings.is_empty());
    }
}
