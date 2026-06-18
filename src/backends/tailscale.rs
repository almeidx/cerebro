//! Parser for `tailscale status --json`.
//!
//! This is the reference parser the other backends mirror: a partial serde
//! deserialization of a captured fixture, mapped onto a model type, with the failure
//! mode funnelled through [`Error::parse`].

use serde::Deserialize;

use crate::error::{Error, Result};
use crate::model::TailscaleStatus;

#[derive(Deserialize)]
struct RawStatus {
    #[serde(rename = "Version")]
    version: Option<String>,
    #[serde(rename = "BackendState")]
    backend_state: Option<String>,
    #[serde(rename = "AuthURL")]
    auth_url: Option<String>,
    #[serde(rename = "Self")]
    self_node: Option<RawNode>,
}

#[derive(Deserialize)]
struct RawNode {
    #[serde(rename = "HostName")]
    host_name: Option<String>,
    #[serde(rename = "DNSName")]
    dns_name: Option<String>,
    #[serde(rename = "TailscaleIPs")]
    ips: Option<Vec<String>>,
    #[serde(rename = "Online")]
    online: Option<bool>,
    #[serde(rename = "PrimaryRoutes")]
    primary_routes: Option<Vec<String>>,
    #[serde(rename = "ExitNode")]
    exit_node: Option<bool>,
}

/// Parse `tailscale status --json` output into a [`TailscaleStatus`].
pub fn parse_status(json: &str) -> Result<TailscaleStatus> {
    let raw: RawStatus =
        serde_json::from_str(json).map_err(|e| Error::parse("tailscale status", e))?;

    let needs_reauth = matches!(
        raw.backend_state.as_deref(),
        Some("NeedsLogin" | "NeedsMachineAuth" | "Stopped")
    ) || raw.auth_url.as_ref().is_some_and(|u| !u.is_empty());

    let node = raw.self_node;
    let online = node.as_ref().and_then(|n| n.online).unwrap_or(false);
    let hostname = node
        .as_ref()
        .and_then(|n| n.host_name.clone().or_else(|| n.dns_name.clone()));
    let addresses = node
        .as_ref()
        .and_then(|n| n.ips.clone())
        .unwrap_or_default();
    let routes = node
        .as_ref()
        .and_then(|n| n.primary_routes.clone())
        .unwrap_or_default();
    let exit_node = node.as_ref().and_then(|n| n.exit_node).unwrap_or(false);

    Ok(TailscaleStatus {
        version: raw.version,
        backend_state: raw.backend_state,
        online,
        needs_reauth,
        auth_url: raw
            .auth_url
            .filter(|u| u.starts_with("https://") && !u.contains(['"', '\'', '<', '>'])),
        hostname,
        addresses,
        routes,
        exit_node,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNNING: &str = r#"{
        "Version": "1.78.1",
        "BackendState": "Running",
        "AuthURL": "",
        "Self": {
            "HostName": "coolify-main",
            "DNSName": "coolify-main.tailnet.ts.net.",
            "TailscaleIPs": ["100.101.102.103"],
            "Online": true,
            "PrimaryRoutes": ["10.0.0.0/24"],
            "ExitNode": false
        }
    }"#;

    const NEEDS_LOGIN: &str = r#"{
        "Version": "1.78.1",
        "BackendState": "NeedsLogin",
        "AuthURL": "https://login.tailscale.com/a/deadbeef",
        "Self": { "HostName": "child-01", "Online": false }
    }"#;

    #[test]
    fn parses_running_node() {
        let s = parse_status(RUNNING).unwrap();
        assert!(s.online);
        assert!(!s.needs_reauth);
        assert_eq!(s.hostname.as_deref(), Some("coolify-main"));
        assert_eq!(s.addresses, vec!["100.101.102.103".to_string()]);
        assert_eq!(s.routes, vec!["10.0.0.0/24".to_string()]);
    }

    #[test]
    fn flags_reauth_and_surfaces_url() {
        let s = parse_status(NEEDS_LOGIN).unwrap();
        assert!(s.needs_reauth);
        assert!(!s.online);
        assert_eq!(
            s.auth_url.as_deref(),
            Some("https://login.tailscale.com/a/deadbeef")
        );
    }

    #[test]
    fn malformed_json_is_a_parse_error() {
        assert!(parse_status("not json").is_err());
    }
}
