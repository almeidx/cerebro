//! Cerebro — a plug-and-play CLI + local web dashboard for managing and securing a fleet
//! of Linux servers over Tailscale SSH.
//!
//! The crate is organized as a set of mostly-pure layers built on a single shared
//! [`model`]:
//!
//! * [`ssh`] — agentless command execution behind the [`ssh::CommandRunner`] trait.
//! * [`backends`] — pure parsers turning raw command output into model types.
//! * [`config`] — the `cerebro.toml` inventory.
//! * [`engine`] — gathering, the safety gate, the security audit, drift and firewall ops.
//! * [`db`] — SQLite persistence (cache, audit log, snapshots, firewall backups).
//! * [`web`] — the axum dashboard served by `cerebro serve`.
//! * [`cli`] — the command-line surface.

pub mod backends;
pub mod cli;
pub mod config;
pub mod db;
pub mod engine;
pub mod error;
pub mod model;
pub mod ssh;
pub mod web;

pub use error::{Error, Result};
