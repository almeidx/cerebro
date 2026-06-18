# cerebro

One console to see and secure your whole fleet.

Cerebro is a single-binary CLI and local web dashboard for managing Linux
servers over Tailscale SSH. It is agentless, inspect-first, and production-safe
by default: every write path is meant to be diffed, confirmed, audited, and
reversible where the underlying system allows it.

```sh
cerebro serve
cerebro audit
cerebro fw status
cerebro updates --security-only
```

First-class targets are CentOS Stream 10 and Rocky Linux 10 with firewalld, dnf,
Docker/Coolify workloads, classic cron, and Tailscale SSH.

## Install

Preferred:

```sh
brew install almeidx/tap/cerebro
```

This installs the prebuilt GitHub Release artifact for Apple Silicon macOS or
Linux (`x86_64` / `aarch64`).

From crates.io:

```sh
cargo install cerebro
```

Or download a release archive directly from
[GitHub Releases](https://github.com/almeidx/cerebro/releases). Verify with the
published SHA-256 checksums.

## Quick start

Create a `cerebro.toml` inventory, then start the local dashboard:

```sh
cerebro serve
```

The dashboard binds to `127.0.0.1` and opens a browser tab. It is a local
control-plane UI; use SSH or Tailscale forwarding rather than exposing it
directly.

Headless commands stay scriptable:

```sh
cerebro audit --json
cerebro fw status
cerebro updates --security-only
```

## What It Checks

- Firewall posture across public, private, and tailnet interfaces.
- External exposure from listening sockets, Docker-published ports, and zone
  assignments.
- SSH hardening, SELinux, fail2ban/CrowdSec signals, Tailscale status, and host
  reachability.
- dnf security errata, reboot state, stale container images, cron jobs, and
  configuration drift snapshots.

## Safety Model

Cerebro shells out to system `ssh`, so your OpenSSH config, known hosts,
ssh-agent, and Tailscale SSH identity are reused. Managed hosts do not need a
daemon.

Mutation paths are explicit. Firewall edits use service presets, raw ports, and
source-restricted rich rules, then show a diff and use an auto-rollback timer so
a bad rule does not lock you out. Bulk actions are serial/canary by default,
with per-host results and a global read-only switch.

## Status

Early development; interfaces and workflows may still change.

## Development

Requires a stable Rust toolchain (Rust 1.96 or newer). SQLite is compiled in,
so no system SQLite dependency is required.

```sh
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

CI runs the test suite and builds the release targets. Merging a release PR
publishes `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl`,
and `aarch64-apple-darwin` binaries with SHA-256 checksums.

License: Apache-2.0.
