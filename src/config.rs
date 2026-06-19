//! Loading and validation of `cerebro.toml`.
//!
//! The configuration file declares fleet-wide [`Settings`] and the list of managed
//! [`HostConfig`] entries. Parsing funnels through [`Config::from_toml_str`] (with
//! `toml::de::Error` surfaced via [`crate::error::Error`]) and semantic checks live in
//! [`Config::validate`], reporting via [`crate::error::Error::Config`].

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::model::InterfaceRole;
use crate::ssh::SshTarget;

/// Top-level parsed `cerebro.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub settings: Settings,
    #[serde(default, rename = "host")]
    pub hosts: Vec<HostConfig>,
}

/// Fleet-wide behaviour knobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub poll_interval_secs: u64,
    pub ssh_connect_timeout: u64,
    pub rollback_timer_secs: u64,
    pub read_only: bool,
    pub parallel_apply: bool,
    pub bind_port: u16,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            poll_interval_secs: 45,
            ssh_connect_timeout: 8,
            rollback_timer_secs: 60,
            read_only: false,
            parallel_apply: false,
            bind_port: 7878,
        }
    }
}

/// A single managed host entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    pub name: String,
    pub address: String,
    #[serde(default = "default_user")]
    pub user: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub interfaces: BTreeMap<String, InterfaceRole>,
}

fn default_user() -> String {
    "root".to_string()
}

fn default_port() -> u16 {
    22
}

impl Config {
    /// Parse `cerebro.toml` contents from a string.
    pub fn from_toml_str(s: &str) -> Result<Self> {
        let config = toml::from_str(s)?;
        Ok(config)
    }

    /// Read, parse and validate a `cerebro.toml` from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let contents =
            std::fs::read_to_string(path).map_err(|source| Error::config_read(path, source))?;
        let config = Self::from_toml_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    /// Reject configurations that are structurally valid TOML but semantically broken.
    pub fn validate(&self) -> Result<()> {
        if self.hosts.is_empty() {
            return Err(Error::Config("no hosts configured".to_string()));
        }

        let mut seen = std::collections::HashSet::new();
        for host in &self.hosts {
            if host.name.trim().is_empty() {
                return Err(Error::Config("host with empty name".to_string()));
            }
            if host.address.trim().is_empty() {
                return Err(Error::Config(format!(
                    "host {} has empty address",
                    host.name
                )));
            }
            if !seen.insert(host.name.as_str()) {
                return Err(Error::Config(format!("duplicate host name: {}", host.name)));
            }
        }

        Ok(())
    }

    /// Look up a host entry by its logical name.
    pub fn host(&self, name: &str) -> Option<&HostConfig> {
        self.hosts.iter().find(|h| h.name == name)
    }
}

impl HostConfig {
    /// Build the [`SshTarget`] used to reach this host, applying fleet [`Settings`].
    pub fn ssh_target(&self, settings: &Settings) -> SshTarget {
        SshTarget {
            host: self.name.clone(),
            address: self.address.clone(),
            user: self.user.clone(),
            port: self.port,
            connect_timeout: Duration::from_secs(settings.ssh_connect_timeout),
            control_path: None,
        }
    }

    /// The operator-assigned role for `iface`, defaulting to [`InterfaceRole::Unknown`].
    pub fn interface_role(&self, iface: &str) -> InterfaceRole {
        self.interfaces
            .get(iface)
            .copied()
            .unwrap_or(InterfaceRole::Unknown)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"
[settings]
poll_interval_secs = 45
read_only = false
bind_port = 7878

[[host]]
name = "coolify-main"
address = "coolify-main"
groups = ["prod", "coolify"]
[host.interfaces]
eth0 = "public"
eth1 = "private"
tailscale0 = "tailnet"
"#;

    #[test]
    fn parses_fixture_with_one_host() {
        let config = Config::from_toml_str(FIXTURE).unwrap();
        assert_eq!(config.hosts.len(), 1);
        let host = &config.hosts[0];
        assert_eq!(host.name, "coolify-main");
        assert_eq!(host.address, "coolify-main");
        assert_eq!(host.groups, vec!["prod".to_string(), "coolify".to_string()]);
    }

    #[test]
    fn applies_settings_defaults_for_omitted_fields() {
        let config = Config::from_toml_str(FIXTURE).unwrap();
        assert_eq!(config.settings.poll_interval_secs, 45);
        assert_eq!(config.settings.bind_port, 7878);
        assert_eq!(config.settings.ssh_connect_timeout, 8);
        assert_eq!(config.settings.rollback_timer_secs, 60);
        assert!(!config.settings.read_only);
        assert!(!config.settings.parallel_apply);
    }

    #[test]
    fn settings_default_matches_spec() {
        let settings = Settings::default();
        assert_eq!(settings.poll_interval_secs, 45);
        assert_eq!(settings.ssh_connect_timeout, 8);
        assert_eq!(settings.rollback_timer_secs, 60);
        assert!(!settings.read_only);
        assert!(!settings.parallel_apply);
        assert_eq!(settings.bind_port, 7878);
    }

    #[test]
    fn empty_config_uses_all_defaults() {
        let config = Config::from_toml_str("").unwrap();
        assert!(config.hosts.is_empty());
        assert_eq!(config.settings.bind_port, 7878);
    }

    #[test]
    fn host_defaults_user_and_port() {
        let config = Config::from_toml_str(FIXTURE).unwrap();
        let host = &config.hosts[0];
        assert_eq!(host.user, "root");
        assert_eq!(host.port, 22);
    }

    #[test]
    fn interface_role_lookup() {
        let config = Config::from_toml_str(FIXTURE).unwrap();
        let host = &config.hosts[0];
        assert_eq!(host.interface_role("eth0"), InterfaceRole::Public);
        assert_eq!(host.interface_role("eth1"), InterfaceRole::Private);
        assert_eq!(host.interface_role("tailscale0"), InterfaceRole::Tailnet);
        assert_eq!(host.interface_role("nope"), InterfaceRole::Unknown);
    }

    #[test]
    fn validate_accepts_fixture() {
        let config = Config::from_toml_str(FIXTURE).unwrap();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_rejects_empty_host_list() {
        let config = Config::from_toml_str("").unwrap();
        let err = config.validate().unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn validate_rejects_duplicate_host_names() {
        let toml = r#"
[[host]]
name = "dup"
address = "a"

[[host]]
name = "dup"
address = "b"
"#;
        let config = Config::from_toml_str(toml).unwrap();
        let err = config.validate().unwrap_err();
        match err {
            Error::Config(msg) => assert!(msg.contains("duplicate")),
            other => panic!("expected Config error, got {other:?}"),
        }
    }

    #[test]
    fn validate_rejects_empty_name() {
        let toml = r#"
[[host]]
name = ""
address = "a"
"#;
        let config = Config::from_toml_str(toml).unwrap();
        assert!(matches!(config.validate(), Err(Error::Config(_))));
    }

    #[test]
    fn validate_rejects_empty_address() {
        let toml = r#"
[[host]]
name = "h"
address = ""
"#;
        let config = Config::from_toml_str(toml).unwrap();
        assert!(matches!(config.validate(), Err(Error::Config(_))));
    }

    #[test]
    fn host_lookup_by_name() {
        let config = Config::from_toml_str(FIXTURE).unwrap();
        assert!(config.host("coolify-main").is_some());
        assert!(config.host("missing").is_none());
    }

    #[test]
    fn ssh_target_uses_defaults_and_settings_timeout() {
        let config = Config::from_toml_str(FIXTURE).unwrap();
        let host = &config.hosts[0];
        let target = host.ssh_target(&config.settings);
        assert_eq!(target.host, "coolify-main");
        assert_eq!(target.address, "coolify-main");
        assert_eq!(target.user, "root");
        assert_eq!(target.port, 22);
        assert_eq!(target.connect_timeout, Duration::from_secs(8));
        assert!(target.control_path.is_none());
    }

    #[test]
    fn ssh_target_honours_custom_user_and_port() {
        let toml = r#"
[settings]
ssh_connect_timeout = 12

[[host]]
name = "edge"
address = "10.0.0.5"
user = "admin"
port = 2222
"#;
        let config = Config::from_toml_str(toml).unwrap();
        let host = &config.hosts[0];
        let target = host.ssh_target(&config.settings);
        assert_eq!(target.user, "admin");
        assert_eq!(target.port, 2222);
        assert_eq!(target.connect_timeout, Duration::from_secs(12));
    }

    #[test]
    fn load_reads_validates_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cerebro.toml");
        std::fs::write(&path, FIXTURE).unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.hosts.len(), 1);
    }

    #[test]
    fn load_propagates_validation_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.toml");
        std::fs::write(&path, "").unwrap();
        assert!(matches!(Config::load(&path), Err(Error::Config(_))));
    }

    #[test]
    fn load_missing_file_names_the_config_path() {
        let path = Path::new("/nonexistent/cerebro/does-not-exist.toml");
        let err = Config::load(path).unwrap_err();
        let message = err.to_string();
        match err {
            Error::MissingConfig { path: missing } => {
                assert_eq!(missing, path);
                assert!(message.contains("--config PATH"));
            }
            other => panic!("expected MissingConfig error, got {other:?}"),
        }
    }

    #[test]
    fn malformed_toml_is_a_parse_error() {
        assert!(matches!(
            Config::from_toml_str("this is not = = toml"),
            Err(Error::Toml(_))
        ));
    }
}
