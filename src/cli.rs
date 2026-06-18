//! Command-line interface definition.
//!
//! This module is parse-only: it declares the clap 4 derive types and a thin
//! [`parse`] helper. Dispatch and execution live elsewhere so the surface here can be
//! exercised in isolation with [`Cli::try_parse_from`].

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Manage and secure a fleet of Linux servers over Tailscale SSH.
#[derive(Debug, Parser)]
#[command(
    name = "cerebro",
    version,
    about = "Manage and secure a fleet of Linux servers over Tailscale SSH"
)]
pub struct Cli {
    /// Refuse every mutating operation, regardless of subcommand.
    #[arg(long, global = true)]
    pub read_only: bool,

    /// Show what would change without touching any host.
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Path to an alternate `cerebro.toml`.
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Fan operations out across hosts concurrently.
    #[arg(long, global = true)]
    pub parallel: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the local web dashboard.
    Serve {
        /// Bind port; defaults to `settings.bind_port` from cerebro.toml (else 7878).
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        no_open: bool,
    },
    /// List inventory + health.
    Hosts,
    /// Show details for one host.
    Host { name: String },
    /// External-exposure security audit.
    Audit {
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Firewall operations.
    Fw {
        #[command(subcommand)]
        cmd: FwCommand,
    },
    /// Pending OS errata + stale images.
    Updates {
        #[arg(long)]
        security_only: bool,
        #[arg(long)]
        json: bool,
    },
    /// Docker / Coolify containers.
    Docker {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Crontab listing.
    Cron {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Tailscale status.
    Tailscale {
        #[arg(long)]
        json: bool,
    },
    /// Take a config snapshot now.
    Snapshot {
        #[arg(long)]
        host: Option<String>,
    },
    /// Show drift since last snapshot.
    Drift {
        #[arg(long)]
        host: Option<String>,
    },
    /// Validate cerebro.toml.
    Config {
        #[command(subcommand)]
        cmd: ConfigCommand,
    },
}

/// Firewall sub-subcommands.
#[derive(Debug, Subcommand)]
pub enum FwCommand {
    /// Firewall posture per host/zone.
    Status {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

/// Config sub-subcommands.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Lint cerebro.toml.
    Validate,
}

/// Parse the process arguments, exiting the program on error or `--help`.
pub fn parse() -> Cli {
    Cli::parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_serve_with_port_and_no_open() {
        let cli = Cli::try_parse_from(["cerebro", "serve", "--port", "9000", "--no-open"]).unwrap();
        match cli.command {
            Command::Serve { port, no_open } => {
                assert_eq!(port, Some(9000));
                assert!(no_open);
            }
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    #[test]
    fn serve_port_is_none_when_omitted() {
        let cli = Cli::try_parse_from(["cerebro", "serve"]).unwrap();
        match cli.command {
            Command::Serve { port, no_open } => {
                assert_eq!(port, None);
                assert!(!no_open);
            }
            other => panic!("expected Serve, got {other:?}"),
        }
    }

    #[test]
    fn global_read_only_flag_applies_before_subcommand() {
        let cli = Cli::try_parse_from(["cerebro", "--read-only", "audit", "--json"]).unwrap();
        assert!(cli.read_only);
        match cli.command {
            Command::Audit { json, group } => {
                assert!(json);
                assert!(group.is_none());
            }
            other => panic!("expected Audit, got {other:?}"),
        }
    }

    #[test]
    fn host_takes_positional_name() {
        let cli = Cli::try_parse_from(["cerebro", "host", "web1"]).unwrap();
        match cli.command {
            Command::Host { name } => assert_eq!(name, "web1"),
            other => panic!("expected Host, got {other:?}"),
        }
    }

    #[test]
    fn fw_status_parses_nested_host_flag() {
        let cli = Cli::try_parse_from(["cerebro", "fw", "status", "--host", "db1"]).unwrap();
        match cli.command {
            Command::Fw {
                cmd: FwCommand::Status { host, json },
            } => {
                assert_eq!(host.as_deref(), Some("db1"));
                assert!(!json);
            }
            other => panic!("expected Fw::Status, got {other:?}"),
        }
    }

    #[test]
    fn config_validate_parses() {
        let cli = Cli::try_parse_from(["cerebro", "config", "validate"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Config {
                cmd: ConfigCommand::Validate
            }
        ));
    }

    #[test]
    fn unknown_subcommand_is_an_error() {
        let result = Cli::try_parse_from(["cerebro", "bogus-cmd"]);
        assert!(result.is_err());
    }

    #[test]
    fn global_flags_accepted_after_subcommand() {
        let cli = Cli::try_parse_from([
            "cerebro",
            "snapshot",
            "--dry-run",
            "--config",
            "/etc/cerebro.toml",
            "--host",
            "edge",
        ])
        .unwrap();
        assert!(cli.dry_run);
        assert_eq!(
            cli.config.as_deref(),
            Some(std::path::Path::new("/etc/cerebro.toml"))
        );
        match cli.command {
            Command::Snapshot { host } => assert_eq!(host.as_deref(), Some("edge")),
            other => panic!("expected Snapshot, got {other:?}"),
        }
    }

    #[test]
    fn updates_security_only_flag() {
        let cli = Cli::try_parse_from(["cerebro", "updates", "--security-only"]).unwrap();
        match cli.command {
            Command::Updates {
                security_only,
                json,
            } => {
                assert!(security_only);
                assert!(!json);
            }
            other => panic!("expected Updates, got {other:?}"),
        }
    }

    #[test]
    fn bare_hosts_subcommand_parses() {
        let cli = Cli::try_parse_from(["cerebro", "hosts"]).unwrap();
        assert!(matches!(cli.command, Command::Hosts));
    }

    #[test]
    fn missing_subcommand_is_an_error() {
        assert!(Cli::try_parse_from(["cerebro"]).is_err());
    }

    #[test]
    fn parallel_global_flag_sets_field() {
        let cli = Cli::try_parse_from(["cerebro", "--parallel", "hosts"]).unwrap();
        assert!(cli.parallel);
    }
}
