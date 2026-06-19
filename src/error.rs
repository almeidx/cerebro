//! Crate-wide error type.

use std::path::PathBuf;

use thiserror::Error;

/// All recoverable errors surfaced by Cerebro.
#[derive(Debug, Error)]
pub enum Error {
    /// The SSH transport itself failed (connection refused, timeout, host key, ...).
    #[error("ssh to {host} failed: {message}")]
    Ssh { host: String, message: String },

    /// Tailscale SSH requires interactive browser re-authentication for this host.
    #[error("{host} needs Tailscale re-authentication")]
    NeedsReauth {
        host: String,
        auth_url: Option<String>,
    },

    /// A remote command ran but exited non-zero.
    #[error("command on {host} exited with status {code}: {stderr}")]
    RemoteCommand {
        host: String,
        code: i32,
        stderr: String,
    },

    /// Failed to parse the output of a remote command.
    #[error("failed to parse {what}: {message}")]
    Parse { what: String, message: String },

    /// Invalid or inconsistent configuration.
    #[error("configuration error: {0}")]
    Config(String),

    /// The requested configuration file does not exist.
    #[error(
        "configuration file not found at {path}; create it from cerebro.example.toml, pass --config PATH, or set CEREBRO_CONFIG"
    )]
    MissingConfig { path: PathBuf },

    /// The requested configuration file exists but could not be read.
    #[error("failed to read configuration file {path}: {source}")]
    ConfigIo {
        path: PathBuf,
        source: std::io::Error,
    },

    /// A mutation was refused by the safety policy (read-only mode, etc.).
    #[error("operation blocked by safety policy: {0}")]
    Blocked(String),

    /// The requested host was not found in the inventory.
    #[error("unknown host: {0}")]
    UnknownHost(String),

    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    Toml(#[from] toml::de::Error),
}

impl Error {
    /// Build a [`Error::Parse`] from any displayable cause.
    pub fn parse(what: impl Into<String>, message: impl std::fmt::Display) -> Self {
        Self::Parse {
            what: what.into(),
            message: message.to_string(),
        }
    }

    /// Build the most useful configuration-read error for a failed path.
    pub fn config_read(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        let path = path.into();
        if source.kind() == std::io::ErrorKind::NotFound {
            Self::MissingConfig { path }
        } else {
            Self::ConfigIo { path, source }
        }
    }
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
