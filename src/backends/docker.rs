//! Parsers for Docker state.
//!
//! Two read-only views: [`parse_ps`] turns `docker ps -a --format {{json .}}` (one JSON
//! object per line) into [`Container`] values, and [`daemon_json_findings`] audits a
//! `/etc/docker/daemon.json` against a handful of production best practices. Both mirror
//! the reference backends: partial serde deserialization, errors funnelled through
//! [`Error::parse`], and captured fixtures in the test module.

use serde::Deserialize;
use serde_json::Value;

use crate::error::Result;
use crate::model::{Container, Finding, FindingCategory, PortMapping, Protocol, Severity};

#[derive(Deserialize)]
struct RawContainer {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Names")]
    names: String,
    #[serde(rename = "Image")]
    image: String,
    #[serde(rename = "State", default)]
    state: String,
    #[serde(rename = "Status", default)]
    status: String,
    #[serde(rename = "Ports", default)]
    ports: String,
    #[serde(rename = "Labels", default)]
    labels: String,
}

fn health_from_status(status: &str) -> Option<String> {
    if status.contains("(healthy)") {
        Some("healthy".to_string())
    } else if status.contains("(unhealthy)") {
        Some("unhealthy".to_string())
    } else if status.contains("(health: starting)") {
        Some("starting".to_string())
    } else {
        None
    }
}

fn compose_project_from_labels(labels: &str) -> Option<String> {
    labels
        .split(',')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| key.trim() == "com.docker.compose.project")
        .map(|(_, value)| value.trim().to_string())
}

fn split_proto(spec: &str) -> (&str, Protocol) {
    if let Some(rest) = spec.strip_suffix("/udp") {
        (rest, Protocol::Udp)
    } else if let Some(rest) = spec.strip_suffix("/tcp") {
        (rest, Protocol::Tcp)
    } else {
        (spec, Protocol::Tcp)
    }
}

/// Split `host:port` from the right so IPv6 literals keep their colons.
fn split_host_port(binding: &str) -> (String, String) {
    match binding.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.to_string()),
        None => (String::new(), binding.to_string()),
    }
}

fn parse_port_entry(entry: &str) -> Option<PortMapping> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }

    if let Some((binding, container)) = entry.split_once("->") {
        let (container_spec, protocol) = split_proto(container.trim());
        let (host_ip, host_port) = split_host_port(binding.trim());
        Some(PortMapping {
            host_ip: Some(host_ip),
            host_port: Some(host_port),
            container_port: container_spec.to_string(),
            protocol,
        })
    } else {
        let (container_spec, protocol) = split_proto(entry);
        Some(PortMapping {
            host_ip: None,
            host_port: None,
            container_port: container_spec.to_string(),
            protocol,
        })
    }
}

fn parse_ports(ports: &str) -> Vec<PortMapping> {
    ports.split(", ").filter_map(parse_port_entry).collect()
}

/// Parse `docker ps -a --format {{json .}}` (one JSON object per line) into [`Container`]s.
///
/// A single malformed line is skipped (and logged) rather than discarding the whole
/// inventory — one weird container should never blind the dashboard to the rest.
pub fn parse_ps(raw: &str) -> Result<Vec<Container>> {
    let mut containers = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let parsed: RawContainer = match serde_json::from_str(line) {
            Ok(parsed) => parsed,
            Err(e) => {
                tracing::warn!(error = %e, line, "skipping unparseable docker ps line");
                continue;
            }
        };
        containers.push(Container {
            id: parsed.id,
            name: parsed.names,
            image: parsed.image,
            image_digest: None,
            state: parsed.state,
            health: health_from_status(&parsed.status),
            status: parsed.status,
            ports: parse_ports(&parsed.ports),
            restart_policy: None,
            compose_project: compose_project_from_labels(&parsed.labels),
        });
    }
    Ok(containers)
}

fn finding(
    id: &str,
    title: &str,
    severity: Severity,
    detail: &str,
    recommendation: &str,
) -> Finding {
    Finding {
        id: id.to_string(),
        title: title.to_string(),
        severity,
        category: FindingCategory::Docker,
        detail: detail.to_string(),
        recommendation: Some(recommendation.to_string()),
    }
}

/// Audit the contents of `/etc/docker/daemon.json` for common hardening gaps.
pub fn daemon_json_findings(content: &str) -> Vec<Finding> {
    let Ok(value) = serde_json::from_str::<Value>(content) else {
        return vec![finding(
            "docker.daemon_unreadable",
            "Docker daemon.json is missing or unreadable",
            Severity::Moderate,
            "Could not parse /etc/docker/daemon.json as JSON.",
            "Ensure /etc/docker/daemon.json exists and contains valid JSON.",
        )];
    };

    let mut findings = Vec::new();

    if value.get("live-restore").and_then(Value::as_bool) != Some(true) {
        findings.push(finding(
            "docker.live_restore",
            "live-restore is not enabled",
            Severity::Moderate,
            "Containers stop when the Docker daemon restarts.",
            "Set \"live-restore\": true so containers survive daemon restarts in production.",
        ));
    }

    let log_driver = value.get("log-driver").and_then(Value::as_str);
    if !matches!(log_driver, Some("json-file" | "local")) {
        findings.push(finding(
            "docker.log_driver",
            "log-driver is unset or unsupported",
            Severity::Low,
            "No bounded log driver is configured for the daemon.",
            "Set \"log-driver\" to \"json-file\" or \"local\".",
        ));
    }

    if log_driver == Some("json-file") {
        let opts = value.get("log-opts");
        let has_opt = |key: &str| opts.and_then(|o| o.get(key)).is_some_and(|v| !v.is_null());
        if !has_opt("max-size") || !has_opt("max-file") {
            findings.push(finding(
                "docker.log_rotation",
                "json-file logs are not rotated",
                Severity::Low,
                "log-opts is missing max-size or max-file, so container logs grow unbounded.",
                "Add \"log-opts\": { \"max-size\": \"10m\", \"max-file\": \"3\" }.",
            ));
        }
    }

    if value.get("userland-proxy").and_then(Value::as_bool) != Some(false) {
        findings.push(finding(
            "docker.userland_proxy",
            "userland-proxy is not disabled",
            Severity::Low,
            "The userland proxy is enabled, adding overhead and masking source IPs.",
            "Set \"userland-proxy\": false.",
        ));
    }

    if value.get("no-new-privileges").and_then(Value::as_bool) != Some(true) {
        findings.push(finding(
            "docker.no_new_privileges",
            "no-new-privileges is not enabled by default",
            Severity::Low,
            "Containers can gain privileges through setuid binaries by default.",
            "Set \"no-new-privileges\": true.",
        ));
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    const PS_TWO: &str = r#"
{"ID":"abc123def456","Image":"nginx:1.27","Names":"myapp-web-1","State":"running","Status":"Up 2 days (healthy)","Ports":"0.0.0.0:8080->80/tcp, :::8080->80/tcp","Labels":"com.docker.compose.project=myapp,com.docker.compose.service=web"}
{"ID":"fff999aaa000","Image":"postgres:16","Names":"myapp-db-1","State":"running","Status":"Up 3 days","Ports":"5432/tcp","Labels":"com.docker.compose.project=myapp,com.docker.compose.service=db"}
"#;

    #[test]
    fn parses_two_line_ps_fixture() {
        let containers = parse_ps(PS_TWO).unwrap();
        assert_eq!(containers.len(), 2);

        let web = &containers[0];
        assert_eq!(web.id, "abc123def456");
        assert_eq!(web.name, "myapp-web-1");
        assert_eq!(web.image, "nginx:1.27");
        assert_eq!(web.health.as_deref(), Some("healthy"));
        assert_eq!(web.compose_project.as_deref(), Some("myapp"));
        assert!(web.is_publicly_exposed());

        let db = &containers[1];
        assert_eq!(db.compose_project.as_deref(), Some("myapp"));
        assert!(db.health.is_none());
        assert!(!db.is_publicly_exposed());
    }

    #[test]
    fn parses_port_mappings_with_ipv6_and_proto() {
        let containers = parse_ps(PS_TWO).unwrap();
        let web = &containers[0];
        assert_eq!(web.ports.len(), 2);

        let v4 = &web.ports[0];
        assert_eq!(v4.host_ip.as_deref(), Some("0.0.0.0"));
        assert_eq!(v4.host_port.as_deref(), Some("8080"));
        assert_eq!(v4.container_port, "80");
        assert_eq!(v4.protocol, Protocol::Tcp);

        let v6 = &web.ports[1];
        assert_eq!(v6.host_ip.as_deref(), Some("::"));
        assert_eq!(v6.host_port.as_deref(), Some("8080"));
        assert_eq!(v6.container_port, "80");

        let db = &containers[1];
        assert_eq!(db.ports.len(), 1);
        let internal = &db.ports[0];
        assert!(internal.host_ip.is_none());
        assert!(internal.host_port.is_none());
        assert_eq!(internal.container_port, "5432");
        assert_eq!(internal.protocol, Protocol::Tcp);
    }

    #[test]
    fn detects_unhealthy_and_starting_health() {
        assert_eq!(
            health_from_status("Up 1 min (unhealthy)").as_deref(),
            Some("unhealthy")
        );
        assert_eq!(
            health_from_status("Up 5 seconds (health: starting)").as_deref(),
            Some("starting")
        );
        assert!(health_from_status("Exited (0) 2 hours ago").is_none());
    }

    #[test]
    fn parses_udp_port() {
        let raw = r#"{"ID":"d1","Image":"coredns","Names":"dns","State":"running","Status":"Up","Ports":"0.0.0.0:53->53/udp","Labels":""}"#;
        let containers = parse_ps(raw).unwrap();
        let port = &containers[0].ports[0];
        assert_eq!(port.protocol, Protocol::Udp);
        assert_eq!(port.container_port, "53");
        assert!(containers[0].compose_project.is_none());
    }

    #[test]
    fn blank_lines_are_skipped() {
        let containers = parse_ps("\n\n   \n").unwrap();
        assert!(containers.is_empty());
    }

    #[test]
    fn malformed_line_is_skipped_and_valid_lines_survive() {
        let raw = concat!(
            r#"{"ID":"a1","Image":"nginx","Names":"web","State":"running","Status":"Up","Ports":"","Labels":""}"#,
            "\n",
            "garbage not json\n",
            r#"{"ID":"b2","Image":"redis","Names":"cache","State":"running","Status":"Up","Ports":"","Labels":""}"#,
            "\n",
        );
        let containers = parse_ps(raw).unwrap();
        assert_eq!(containers.len(), 2);
        assert_eq!(containers[0].id, "a1");
        assert_eq!(containers[1].id, "b2");
    }

    #[test]
    fn container_missing_state_still_parses() {
        let raw = r#"{"ID":"x1","Image":"busybox","Names":"box","Ports":"","Labels":""}"#;
        let containers = parse_ps(raw).unwrap();
        assert_eq!(containers.len(), 1);
        assert_eq!(containers[0].state, "");
        assert!(containers[0].health.is_none());
    }

    const COMPLIANT: &str = r#"{
        "live-restore": true,
        "log-driver": "json-file",
        "log-opts": { "max-size": "10m", "max-file": "3" },
        "userland-proxy": false,
        "no-new-privileges": true
    }"#;

    #[test]
    fn compliant_config_has_no_findings() {
        assert!(daemon_json_findings(COMPLIANT).is_empty());
    }

    #[test]
    fn empty_config_flags_every_default() {
        let findings = daemon_json_findings("{}");
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"docker.live_restore"));
        assert!(ids.contains(&"docker.log_driver"));
        assert!(ids.contains(&"docker.userland_proxy"));
        assert!(ids.contains(&"docker.no_new_privileges"));
        assert!(!ids.contains(&"docker.log_rotation"));
        assert!(findings
            .iter()
            .all(|f| f.category == FindingCategory::Docker));
    }

    #[test]
    fn json_file_without_rotation_is_flagged() {
        let config = r#"{
            "live-restore": true,
            "log-driver": "json-file",
            "userland-proxy": false,
            "no-new-privileges": true
        }"#;
        let ids: Vec<String> = daemon_json_findings(config)
            .into_iter()
            .map(|f| f.id)
            .collect();
        assert!(ids.contains(&"docker.log_rotation".to_string()));
        assert!(!ids.contains(&"docker.log_driver".to_string()));
    }

    #[test]
    fn local_driver_skips_rotation_check() {
        let config = r#"{
            "live-restore": true,
            "log-driver": "local",
            "userland-proxy": false,
            "no-new-privileges": true
        }"#;
        assert!(daemon_json_findings(config).is_empty());
    }

    #[test]
    fn malformed_json_yields_single_unreadable_finding() {
        let findings = daemon_json_findings("{ this is not json");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "docker.daemon_unreadable");
        assert_eq!(findings[0].category, FindingCategory::Docker);
        assert_eq!(findings[0].severity, Severity::Moderate);
    }
}
