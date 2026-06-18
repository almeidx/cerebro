# AGENTS.md

Cerebro is a single-binary Rust CLI plus local web dashboard for inspecting and
carefully managing Linux server fleets over Tailscale SSH. It is agentless:
managed hosts should not need a daemon or installed helper.

## The one rule that outranks everything

**Cerebro is inspect-first and production-safe by default.** Read paths may
gather and cache facts, but write paths must be explicit, diff-reviewed,
audited, and protected by the existing safety model. A convenience shortcut that
can lock out SSH, expose a service, skip rollback, or silently mutate a host is
wrong.

Practical consequences:
- Remote commands go through the SSH executor and backend traits; do not build
  ad hoc shell strings in UI or command handlers.
- Dashboard and CLI mutation flows must honor read-only mode, dry-run, tiered
  action policy, audit logging, and per-host failure reporting.
- Firewall changes keep the diff + confirmation + auto-rollback path intact.
- Tailscale SSH re-auth is a degraded host state, not a fleet-wide failure.
- The local web server is loopback-only control plane UI. Do not add network
  exposure without an auth design.

## Build / test / lint (CI runs exactly these)

    cargo test
    cargo clippy --all-targets -- -D warnings
    cargo fmt --check

All three must pass before a change is considered done. CI also builds the
static Linux release targets (`x86_64-unknown-linux-musl` and
`aarch64-unknown-linux-musl`).

## Conventions

- Backend code should return structured facts and typed errors; keep parsing and
  command construction close to the backend that owns the remote tool.
- Prefer additive JSON/schema changes for CLI output and cached records.
- Keep UI actions reversible where the domain allows it, and surface pending
  rollback timers clearly.
- Do not introduce a Node build requirement for shipped assets.
- Error messages should name the host and operation, and distinguish
  unreachable, auth-required, unsupported, and command-failed states.

## Where things live

- `src/cli.rs` — CLI shape and subcommands.
- `src/main.rs` / `src/lib.rs` — binary entrypoint and library wiring.
- `src/config.rs` — `cerebro.toml` loading and host/settings model.
- `src/ssh/` — system OpenSSH execution and transport behavior.
- `src/backends/` — per-domain remote probes/actions for dnf, Docker,
  firewalld, sockets, cron, Tailscale, and OS facts.
- `src/engine/` — inventory gathering, audits, drift, safety checks, and
  firewall operations.
- `src/db.rs` — SQLite persistence for cache, snapshots, and audit data.
- `src/web/` — axum web server, templates, and embedded dashboard assets.
- `tests/end_to_end.rs` — integration coverage for the current CLI/engine flow.

## Spec

The full design and roadmap live in `SPEC.md`. Treat it as the behavioral
contract when README.md is too high-level.
