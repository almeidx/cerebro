//! Parser and diff engine for `firewall-cmd --list-all-zones`.
//!
//! Mirrors the other backends: a line-oriented parse of a captured fixture mapped onto
//! the shared model, a pure diff against a desired state, and a translation of that diff
//! into concrete `firewall-cmd` argv.

use crate::model::{FirewallBackend, FirewallState, FirewallZone, PortRule, Protocol, ZoneDiff};

/// The state an operator wants a single zone to converge to.
#[derive(Debug, Clone, Default)]
pub struct DesiredZone {
    pub services: Vec<String>,
    pub ports: Vec<PortRule>,
    pub rich_rules: Vec<String>,
}

fn parse_protocol(token: &str) -> Protocol {
    match token.trim().to_ascii_lowercase().as_str() {
        "udp" => Protocol::Udp,
        _ => Protocol::Tcp,
    }
}

fn parse_port_rule(token: &str) -> PortRule {
    match token.split_once('/') {
        Some((port, proto)) => PortRule {
            port: port.to_string(),
            protocol: parse_protocol(proto),
        },
        None => PortRule {
            port: token.to_string(),
            protocol: Protocol::Tcp,
        },
    }
}

fn split_list(value: &str) -> Vec<String> {
    value.split_whitespace().map(str::to_string).collect()
}

fn is_zone_header(line: &str) -> bool {
    !line.is_empty() && !line.starts_with(char::is_whitespace)
}

fn zone_name(header: &str) -> String {
    header
        .trim()
        .strip_suffix(" (active)")
        .unwrap_or_else(|| header.trim())
        .trim()
        .to_string()
}

/// Parse `firewall-cmd --list-all-zones` output into a [`FirewallState`].
pub fn parse_list_all_zones(raw: &str) -> FirewallState {
    let mut zones: Vec<FirewallZone> = Vec::new();
    let mut current: Option<FirewallZone> = None;
    let mut in_rich_rules = false;

    for line in raw.lines() {
        if line.trim().is_empty() {
            in_rich_rules = false;
            continue;
        }

        if is_zone_header(line) {
            if let Some(zone) = current.take() {
                zones.push(zone);
            }
            current = Some(FirewallZone {
                name: zone_name(line),
                ..FirewallZone::default()
            });
            in_rich_rules = false;
            continue;
        }

        let Some(zone) = current.as_mut() else {
            continue;
        };

        let trimmed = line.trim();

        if in_rich_rules {
            if trimmed.starts_with("rule ") || trimmed == "rule" {
                zone.rich_rules.push(trimmed.to_string());
                continue;
            }
            in_rich_rules = false;
        }

        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        match key {
            "interfaces" => zone.interfaces = split_list(value),
            "sources" => zone.sources = split_list(value),
            "services" => zone.services = split_list(value),
            "ports" => {
                zone.ports = value.split_whitespace().map(parse_port_rule).collect();
            }
            "target" => {
                zone.target = if value.is_empty() {
                    None
                } else {
                    Some(value.to_string())
                };
            }
            "rich rules" => in_rich_rules = true,
            _ => {}
        }
    }

    if let Some(zone) = current.take() {
        zones.push(zone);
    }

    FirewallState {
        backend: FirewallBackend::Firewalld,
        zones,
    }
}

fn added<T: Clone + PartialEq>(desired: &[T], current: &[T]) -> Vec<T> {
    desired
        .iter()
        .filter(|d| !current.contains(d))
        .cloned()
        .collect()
}

fn removed<T: Clone + PartialEq>(current: &[T], desired: &[T]) -> Vec<T> {
    current
        .iter()
        .filter(|c| !desired.contains(c))
        .cloned()
        .collect()
}

/// Compute the change set that moves `current` toward `desired`.
pub fn diff_zone(current: &FirewallZone, desired: &DesiredZone) -> ZoneDiff {
    ZoneDiff {
        zone: current.name.clone(),
        added_services: added(&desired.services, &current.services),
        removed_services: removed(&current.services, &desired.services),
        added_ports: added(&desired.ports, &current.ports),
        removed_ports: removed(&current.ports, &desired.ports),
        added_rich_rules: added(&desired.rich_rules, &current.rich_rules),
        removed_rich_rules: removed(&current.rich_rules, &desired.rich_rules),
    }
}

/// Render a [`ZoneDiff`] into one `firewall-cmd` argv per change.
pub fn apply_argv(zone: &str, diff: &ZoneDiff, permanent: bool) -> Vec<Vec<String>> {
    let base = || {
        let mut argv = vec!["firewall-cmd".to_string()];
        if permanent {
            argv.push("--permanent".to_string());
        }
        argv.push(format!("--zone={zone}"));
        argv
    };

    let mut out = Vec::new();

    for service in &diff.added_services {
        let mut argv = base();
        argv.push(format!("--add-service={service}"));
        out.push(argv);
    }
    for service in &diff.removed_services {
        let mut argv = base();
        argv.push(format!("--remove-service={service}"));
        out.push(argv);
    }
    for port in &diff.added_ports {
        let mut argv = base();
        argv.push(format!("--add-port={port}"));
        out.push(argv);
    }
    for port in &diff.removed_ports {
        let mut argv = base();
        argv.push(format!("--remove-port={port}"));
        out.push(argv);
    }
    for rule in &diff.added_rich_rules {
        let mut argv = base();
        argv.push(format!("--add-rich-rule={rule}"));
        out.push(argv);
    }
    for rule in &diff.removed_rich_rules {
        let mut argv = base();
        argv.push(format!("--remove-rich-rule={rule}"));
        out.push(argv);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST_ALL: &str = r#"public (active)
  target: default
  icmp-block-inversion: no
  interfaces: eth0
  sources:
  services: cockpit dhcpv6-client ssh
  ports: 80/tcp 8443/tcp
  protocols:
  forward: yes
  masquerade: no
  rich rules:
      rule family="ipv4" source address="10.0.0.0/24" port port="5432" protocol="tcp" accept

internal (active)
  target: default
  interfaces: eth1
  services: ssh mdns samba-client
  ports:
  rich rules:
"#;

    fn parsed() -> FirewallState {
        parse_list_all_zones(LIST_ALL)
    }

    #[test]
    fn backend_is_firewalld() {
        assert_eq!(parsed().backend, FirewallBackend::Firewalld);
    }

    #[test]
    fn parses_both_zones() {
        let state = parsed();
        assert_eq!(state.zones.len(), 2);
        assert!(state.zone("public").is_some());
        assert!(state.zone("internal").is_some());
    }

    #[test]
    fn strips_active_suffix_from_name() {
        let state = parsed();
        assert_eq!(state.zones[0].name, "public");
        assert_eq!(state.zones[1].name, "internal");
    }

    #[test]
    fn parses_public_zone_fields() {
        let state = parsed();
        let public = state.zone("public").unwrap();
        assert_eq!(public.interfaces, vec!["eth0".to_string()]);
        assert!(public.sources.is_empty());
        assert!(public.services.contains(&"ssh".to_string()));
        assert!(public.services.contains(&"cockpit".to_string()));
        assert_eq!(public.target.as_deref(), Some("default"));
    }

    #[test]
    fn parses_public_ports() {
        let state = parsed();
        let public = state.zone("public").unwrap();
        assert!(public.ports.contains(&PortRule {
            port: "80".to_string(),
            protocol: Protocol::Tcp,
        }));
        assert!(public.ports.contains(&PortRule {
            port: "8443".to_string(),
            protocol: Protocol::Tcp,
        }));
    }

    #[test]
    fn collects_rich_rule() {
        let state = parsed();
        let public = state.zone("public").unwrap();
        assert_eq!(public.rich_rules.len(), 1);
        assert!(public.rich_rules[0].contains("source address=\"10.0.0.0/24\""));
    }

    #[test]
    fn rich_rules_do_not_leak_across_zones() {
        let state = parsed();
        let internal = state.zone("internal").unwrap();
        assert!(internal.rich_rules.is_empty());
        assert!(internal.services.contains(&"ssh".to_string()));
        assert!(internal.ports.is_empty());
        assert_eq!(internal.interfaces, vec!["eth1".to_string()]);
    }

    #[test]
    fn parses_udp_and_port_range() {
        let state = parse_list_all_zones("custom\n  ports: 53/udp 8000-8100/tcp 9000\n");
        let zone = state.zone("custom").unwrap();
        assert_eq!(
            zone.ports[0],
            PortRule {
                port: "53".to_string(),
                protocol: Protocol::Udp,
            }
        );
        assert_eq!(
            zone.ports[1],
            PortRule {
                port: "8000-8100".to_string(),
                protocol: Protocol::Tcp,
            }
        );
        assert_eq!(zone.ports[2].protocol, Protocol::Tcp);
    }

    #[test]
    fn empty_input_yields_no_zones() {
        let state = parse_list_all_zones("");
        assert!(state.zones.is_empty());
        assert_eq!(state.backend, FirewallBackend::Firewalld);
    }

    fn public_zone() -> FirewallZone {
        parse_list_all_zones(LIST_ALL)
            .zone("public")
            .cloned()
            .unwrap()
    }

    #[test]
    fn diff_adds_and_removes_services() {
        let current = public_zone();
        let desired = DesiredZone {
            services: vec!["ssh".to_string(), "https".to_string()],
            ports: current.ports.clone(),
            rich_rules: current.rich_rules.clone(),
        };
        let diff = diff_zone(&current, &desired);
        assert_eq!(diff.zone, "public");
        assert_eq!(diff.added_services, vec!["https".to_string()]);
        assert!(diff.removed_services.contains(&"cockpit".to_string()));
        assert!(diff.removed_services.contains(&"dhcpv6-client".to_string()));
        assert!(diff.added_ports.is_empty());
        assert!(diff.removed_ports.is_empty());
    }

    #[test]
    fn diff_adds_and_removes_ports() {
        let current = public_zone();
        let desired = DesiredZone {
            services: current.services.clone(),
            ports: vec![
                PortRule {
                    port: "80".to_string(),
                    protocol: Protocol::Tcp,
                },
                PortRule {
                    port: "443".to_string(),
                    protocol: Protocol::Tcp,
                },
            ],
            rich_rules: current.rich_rules.clone(),
        };
        let diff = diff_zone(&current, &desired);
        assert_eq!(
            diff.added_ports,
            vec![PortRule {
                port: "443".to_string(),
                protocol: Protocol::Tcp,
            }]
        );
        assert_eq!(
            diff.removed_ports,
            vec![PortRule {
                port: "8443".to_string(),
                protocol: Protocol::Tcp,
            }]
        );
    }

    #[test]
    fn diff_handles_rich_rules() {
        let current = public_zone();
        let desired = DesiredZone {
            services: current.services.clone(),
            ports: current.ports.clone(),
            rich_rules: vec!["rule family=\"ipv4\" service name=\"http\" accept".to_string()],
        };
        let diff = diff_zone(&current, &desired);
        assert_eq!(diff.added_rich_rules.len(), 1);
        assert_eq!(diff.removed_rich_rules.len(), 1);
    }

    #[test]
    fn identical_state_yields_empty_diff() {
        let current = public_zone();
        let desired = DesiredZone {
            services: current.services.clone(),
            ports: current.ports.clone(),
            rich_rules: current.rich_rules.clone(),
        };
        assert!(diff_zone(&current, &desired).is_empty());
    }

    #[test]
    fn apply_argv_emits_permanent_and_zone() {
        let diff = ZoneDiff {
            zone: "public".to_string(),
            added_services: vec!["https".to_string()],
            removed_services: vec!["cockpit".to_string()],
            added_ports: vec![PortRule {
                port: "443".to_string(),
                protocol: Protocol::Tcp,
            }],
            removed_ports: vec![PortRule {
                port: "8443".to_string(),
                protocol: Protocol::Tcp,
            }],
            added_rich_rules: vec!["rule family=\"ipv4\" accept".to_string()],
            removed_rich_rules: vec!["rule family=\"ipv6\" drop".to_string()],
        };
        let argv = apply_argv("public", &diff, true);
        assert_eq!(argv.len(), 6);
        for cmd in &argv {
            assert_eq!(cmd[0], "firewall-cmd");
            assert!(cmd.contains(&"--permanent".to_string()));
            assert!(cmd.contains(&"--zone=public".to_string()));
        }
        assert!(argv
            .iter()
            .any(|c| c.contains(&"--add-service=https".to_string())));
        assert!(argv
            .iter()
            .any(|c| c.contains(&"--remove-service=cockpit".to_string())));
        assert!(argv
            .iter()
            .any(|c| c.contains(&"--add-port=443/tcp".to_string())));
        assert!(argv
            .iter()
            .any(|c| c.contains(&"--remove-port=8443/tcp".to_string())));
        assert!(argv
            .iter()
            .any(|c| c.contains(&"--add-rich-rule=rule family=\"ipv4\" accept".to_string())));
        assert!(argv
            .iter()
            .any(|c| c.contains(&"--remove-rich-rule=rule family=\"ipv6\" drop".to_string())));
    }

    #[test]
    fn apply_argv_omits_permanent_when_runtime() {
        let diff = ZoneDiff {
            zone: "public".to_string(),
            added_services: vec!["ssh".to_string()],
            ..ZoneDiff::default()
        };
        let argv = apply_argv("public", &diff, false);
        assert_eq!(argv.len(), 1);
        assert!(!argv[0].contains(&"--permanent".to_string()));
        assert_eq!(
            argv[0],
            vec![
                "firewall-cmd".to_string(),
                "--zone=public".to_string(),
                "--add-service=ssh".to_string(),
            ]
        );
    }

    #[test]
    fn apply_argv_empty_diff_yields_nothing() {
        let diff = ZoneDiff {
            zone: "public".to_string(),
            ..ZoneDiff::default()
        };
        assert!(apply_argv("public", &diff, true).is_empty());
    }
}
