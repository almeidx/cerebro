//! Distro-specific backends.
//!
//! Each submodule is a set of **pure parsers** that turn raw remote command output into
//! the shared [`crate::model`] types. They take `&str` and return model values or a
//! [`crate::error::Error`] — no I/O — which keeps them trivially unit-testable against
//! captured fixtures.

pub mod cron;
pub mod dnf;
pub mod docker;
pub mod firewalld;
pub mod os_release;
pub mod sockets;
pub mod tailscale;
