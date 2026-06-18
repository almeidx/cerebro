# Cerebro

> One console to see — and secure — your whole fleet.

Cerebro is a plug-and-play CLI **and** local web dashboard for managing and securing a
fleet of Linux servers (first-class targets: **CentOS Stream 10** and **Rocky Linux 10**)
over **Tailscale SSH**. It is **agentless** (nothing is installed on your servers),
**inspect-first** (every change is diffed, confirmed and reversible) and
**production-safe by default**.

```console
$ cerebro serve          # opens the dashboard at http://127.0.0.1:7878
$ cerebro audit          # external-exposure security audit across the fleet (JSON-able)
$ cerebro fw status      # firewall posture per host/zone
$ cerebro updates --security-only
```

## Why

Built for the sysadmin who runs a handful of production boxes and wants a single pane of
glass for: firewall posture, what's actually reachable from the internet, Docker /
Coolify stacks, OS & container security updates, cron jobs and Tailscale status — with
the ability to make careful, auditable changes.

## Highlights

- **Agentless over Tailscale SSH** — shells out to your system `ssh`, so your
  `~/.ssh/config`, `known_hosts` and Tailscale identity auth just work. Detects and
  gracefully surfaces Tailscale's periodic browser re-authentication.
- **Firewall editor** — firewalld zones mapped onto your interfaces (public / private /
  tailnet), with service presets, raw ports and source-restricted rich-rules, a live
  diff, and an **auto-rollback timer** so a bad rule can't lock you out.
- **External-exposure audit** — listening sockets vs firewall zones, SSH hardening,
  SELinux, fail2ban/CrowdSec, pending security errata, and `0.0.0.0` Docker ports.
- **Updates** — dnf security errata (with severity) and stale container images, with
  guided, reboot-aware apply.
- **Safety** — tiered actions, `--dry-run`, a global read-only switch and an append-only
  audit log.

## Status

Early development. See [SPEC.md](SPEC.md) for the full design and roadmap.

## Building

```console
cargo build --release
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

Requires a stable Rust toolchain (≥ 1.82). SQLite is compiled in (no system dependency).

## License

MIT OR Apache-2.0.
