# Cerebro — Specification

> A plug-and-play Rust CLI + local web dashboard for managing and securing a fleet
> of Linux servers (primary targets: CentOS Stream 10 & Rocky Linux 10) over
> Tailscale SSH. Named after Professor X's Cerebro — one console to see the whole fleet.

---

## 1. Vision

Cerebro is a **single-operator sysadmin cockpit**. You run `cerebro serve` on your
workstation, a localhost browser tab opens, and you get one pane of glass over every
server: firewall posture, external exposure, Docker/Coolify stacks, OS & image
security updates, cron jobs, and Tailscale status — with the ability to make
**confirmed, diff-reviewed, auto-rollback-protected** changes.

The guiding principles:

- **Inspect-first.** The dominant value is centralized visibility and audit. Every
  mutation is explicit, diffed, and confirmed.
- **Agentless & plug-and-play.** Nothing is installed on the servers. Everything runs
  as on-demand SSH commands. A server is "onboarded" the moment it's in `cerebro.toml`.
- **Production-safe by default.** Canary sequencing, auto-rollback timers, a global
  read-only switch, dry-run, and an append-only audit log. Cerebro should never be the
  reason a prod box goes dark.
- **Don't get locked in.** Distro/firewall specifics live behind traits so the tool
  isn't welded to dnf/firewalld forever.

---

## 2. Goals & Non-Goals

### Goals
- Centralized, near-real-time view of all servers' security-relevant configuration.
- A friendly-but-powerful firewall editor that understands a multi-interface topology
  (public / private / tailnet) and protects against SSH lockout.
- External-exposure security auditing ("are these boxes safe from the outside?").
- Visibility into Docker containers, Coolify-managed stacks, and cron jobs.
- OS security-errata and stale-Docker-image tracking, with guided, reboot-aware apply.
- Config snapshots with drift highlighting ("what changed since yesterday").

### Non-Goals (v1)
- Not a full configuration-management system (no Ansible/Terraform-style declarative
  desired-state reconciliation). Cerebro is inspect-first with explicit actions.
- No agent/daemon installed on managed hosts.
- No external alerting (Discord/Slack/ntfy/email) or scheduled headless scanning in v1 —
  warnings live in the dashboard while it's running.
- No multi-user/team features, RBAC, or remote-hosted control plane.
- No systemd-timer editing (timers are out of scope; classic crontab only).
- Does not manage Tailscale itself (read-only Tailscale visibility).
- Does not auto-apply firewall changes without review, nor auto-patch without opt-in.

---

## 3. Decisions Locked In (from requirements interview)

| Area | Decision |
|------|----------|
| Execution model | **Agentless** — pure on-demand SSH, nothing installed on hosts |
| Operating model | **Inspect-first**, mutations explicit + confirmed |
| SSH transport | **Shell out to system `ssh`** (inherits `~/.ssh/config`, known_hosts, agent, Tailscale SSH auth) |
| Privilege | **Root over Tailscale SSH** (no sudo, no password); handle Tailscale periodic re-auth gracefully |
| Inventory | **Manual `cerebro.toml`** config file |
| Primary UI | **Local web dashboard** via `cerebro serve` (opens localhost tab); not recommended for prod exposure |
| Dashboard bind | **Localhost only** (127.0.0.1), no network auth |
| Frontend | **Single binary**: axum backend + **SSR HTML + htmx/Alpine**, assets embedded |
| Persistence | **SQLite** + config snapshots/history |
| Data freshness | **Background poll + cache**, per-host "refresh now" |
| Firewall backend | **firewalld-first, behind an abstraction** (ufw a later target) |
| Firewall safety | **Diff + auto-rollback timer** |
| Firewall editor | **Service presets + raw port/proto + source-restricted rich-rules**, per zone, with live diff |
| Multi-interface | Model eth0 (public) / eth1 (Hetzner private) / tailscale as **firewalld zones** |
| Security audit | **External-exposure focused** |
| Docker daemon config | **Audit + recommend only** (advisory; you apply changes) |
| Docker panel | **Inventory + confirmed actions** (restart/redeploy); Dozzle = ordinary container, no special handling |
| Coolify | **Disk/Docker-level only** (read compose/containers over SSH; no Coolify API) |
| Updates | **Track OS errata (dnf updateinfo) + stale Docker images**; **guided, reboot-aware apply** |
| Cron | **Classic crontabs (user + system), editable** behind confirm/safe-mode; no systemd timers |
| Tailscale | **Read-only status** per host |
| Drift | **Snapshot diff surfaced in dashboard** |
| Safe mode | **Tiered actions + dry-run**, **global read-only switch**, **audit-log every change** |
| Orchestration | **Serial/canary apply by default, parallel opt-in**; gathering always parallel |
| Extensibility | **Internal trait abstraction** (PackageManager / Firewall / ServiceManager / …); no external plugin API yet |
| CLI surface | **`serve` + headless scriptable subcommands** (table/JSON output) |

---

## 4. Architecture

### 4.1 Components

```
┌─────────────────────────────────────────────────────────────┐
│ cerebro (single static binary)                               │
│                                                              │
│  CLI (clap)                Web server (axum, 127.0.0.1)      │
│     │                          │   SSR templates + htmx       │
│     └──────────┬───────────────┘   embedded assets           │
│                ▼                                              │
│         Core engine                                          │
│   ┌──────────────────────────────────────────────────────┐  │
│   │ Inventory  │ Scheduler/Poller │ Action orchestrator   │  │
│   │ Safety/policy gate │ Snapshot+Drift │ Audit logger     │  │
│   └──────────────────────────────────────────────────────┘  │
│                ▼                                              │
│         Backend traits (per-host capability)                 │
│   PackageManager · Firewall · ServiceManager · ContainerMgr  │
│   CronManager · TailscaleProbe · SystemFacts                 │
│                ▼                                              │
│         SSH executor (tokio::process → system `ssh`,         │
│                       ControlMaster multiplexing)            │
│                ▼                                              │
│         SQLite (cache · snapshots · audit log · backups)     │
└─────────────────────────────────────────────────────────────┘
                         │ ssh (Tailscale SSH, root)
                         ▼
        ┌────────────┬────────────┬────────────┐
        │  host A     │  host B     │  host C    │  …managed Linux servers
        └────────────┴────────────┴────────────┘
```

### 4.2 Execution model — agentless SSH

- Every read/action is a discrete command executed on the host via the **system OpenSSH
  client** (`tokio::process::Command` invoking `ssh`). This inherits the operator's
  `~/.ssh/config`, `known_hosts`, ssh-agent, and—critically—**Tailscale SSH** identity
  auth transparently.
- **Connection multiplexing:** Cerebro uses OpenSSH `ControlMaster=auto` +
  `ControlPersist` with a per-host control socket under its state dir. A fleet-wide poll
  reuses one TCP/SSH session per host instead of reconnecting per command — fast and low
  overhead despite being "shell out."
- Commands are wrapped to be **non-interactive and deterministic**:
  `ssh -o BatchMode=yes -o ConnectTimeout=… host -- <cmd>`, with structured-output flags
  preferred (`--json`, `-o json`, `firewall-cmd --list-all --permanent`, etc.).
- A small **command-builder layer** centralizes quoting/escaping so we never build shell
  strings ad hoc. Each backend method maps to one well-defined remote command + a parser.

### 4.3 Identity, root, and the Tailscale re-auth edge case

- Default connection: **root over Tailscale SSH**, no password, no sudo. Per-host
  overrides (user, port, jump host) live in `cerebro.toml`.
- **Re-auth detection:** Tailscale SSH periodically requires browser re-authentication
  (the "check mode" login URL). When an SSH attempt fails for this reason, Cerebro:
  1. Recognizes the signature (auth-required exit / check-mode message / connection
     refused with the known pattern).
  2. Marks that host **`needs-reauth` (degraded)** in the dashboard and cache — it is not
     treated as down.
  3. Surfaces the **clickable Tailscale auth URL** when available, plus a "retry" button.
  4. **Isolation:** the rest of the fleet keeps polling/working normally; one host's
     re-auth never blocks the others.
- Health states per host: `online`, `degraded:needs-reauth`, `unreachable`, `unknown`.

### 4.4 Concurrency & orchestration

- **Gathering (reads):** always fan out in **parallel** across the fleet (bounded
  concurrency, e.g. a semaphore) for snappy polls.
- **Applying (writes):** **serial/canary by default** — one host at a time so each acts as
  a natural canary; verify health before proceeding to the next. A **parallel opt-in**
  flag/toggle exists for low-risk bulk operations.
- Per-host **auto-rollback timer** applies to firewall changes regardless of sequencing.
- Partial failure is first-class: an apply across N hosts reports per-host outcomes; a
  failure stops the serial sequence (configurable continue-on-error).

### 4.5 Backend trait abstraction

First-class impls target **dnf + firewalld + systemd** (CentOS Stream 10 / Rocky 10).
Everything distro-specific is behind traits so apt/ufw/Debian are additive later:

```rust
trait SystemFacts   { async fn gather(&self, h: &Host) -> Result<Facts>; }      // OS, kernel, SELinux, uptime, interfaces
trait PackageManager{ async fn list_updates(..); async fn security_errata(..); async fn apply(..); async fn needs_reboot(..); }
trait Firewall      { async fn read_state(..); async fn diff(..); async fn apply_with_rollback(..); async fn backup(..); async fn restore(..); }
trait ServiceManager{ async fn status(..); async fn listening_sockets(..); }    // systemd; ss -tulpen
trait ContainerMgr  { async fn ps(..); async fn inspect(..); async fn daemon_config(..); async fn restart(..); async fn compose_stacks(..); }
trait CronManager   { async fn list(..); async fn upsert(..); async fn disable(..); }
trait TailscaleProbe{ async fn status(..); }                                    // read-only
```

A `HostBackend` is resolved per host from detected distro facts (`/etc/os-release`,
which firewall is active, etc.) and cached.

### 4.6 Web server & frontend

- **axum** on `127.0.0.1:<port>` (default e.g. `7878`); `cerebro serve` opens the browser
  tab automatically.
- **Single self-contained binary:** all HTML/CSS/JS embedded via `rust-embed`.
- **SSR + htmx/Alpine:** server-rendered templates (minijinja or askama), htmx for partial
  updates and form posts, a **WebSocket/SSE channel** to push poll refreshes and
  rollback-timer countdowns live.
- No build-time Node dependency in the shipped artifact (htmx/Alpine vendored as static
  assets). Optional dev tooling only.
- **No auth** — bind is loopback-only; reach remotely via SSH/Tailscale port-forward.
  The UI shows a persistent "control plane — localhost only, do not expose" banner.

---

## 5. Configuration — `cerebro.toml`

Lives at `$XDG_CONFIG_HOME/cerebro/cerebro.toml` (or `--config`). Hand-maintained.

```toml
[settings]
poll_interval_secs   = 45          # background poll cadence
ssh_connect_timeout  = 8
rollback_timer_secs  = 60          # firewall auto-revert window
read_only            = false       # GLOBAL safe-mode switch; blocks all writes when true
parallel_apply       = false       # serial/canary default; true = fan out writes
bind_port            = 7878

# Interface role vocabulary, mapped per host below. Drives firewall zones + audit.
# roles: public | private | tailnet

[[host]]
name        = "coolify-main"
address     = "coolify-main"       # tailnet hostname (resolved via Tailscale SSH)
user        = "root"               # default
port        = 22
groups       = ["prod", "coolify", "public-facing"]
[host.interfaces]
eth0        = "public"             # -> firewalld public zone
eth1        = "private"            # -> firewalld internal zone (Hetzner vSwitch)
tailscale0  = "tailnet"            # -> firewalld trusted/custom zone

[[host]]
name        = "coolify-child-01"
address     = "coolify-child-01"
groups       = ["prod", "coolify-child"]
[host.interfaces]
eth0        = "public"
eth1        = "private"
tailscale0  = "tailnet"
```

- **Groups** enable targeting (`cerebro audit --group prod`, apply-to-group in UI).
- **Interface→role mapping** is what lets the firewall editor and audit reason about
  "reachable from the public internet" vs "private/tailnet only."
- Config is validated on load (`cerebro config validate`); unknown interface roles, dup
  names, etc. are hard errors.

---

## 6. Feature Modules

### 6.1 Inventory & host overview
- Fleet grid: name, groups, health (incl. `needs-reauth`), OS/kernel, SELinux mode,
  uptime, last-poll age, quick badges (open-ports count, pending security errata,
  containers, drift?).
- Drill into a single host → tabbed panels for each module below.

### 6.2 Firewall management *(centerpiece)*
- **Model:** firewalld zones, one per interface role (public / internal / tailnet),
  read via `firewall-cmd --list-all-zones` (permanent + runtime) — behind the `Firewall`
  trait so ufw can be added later.
- **Editor UX (friendly + powerful):**
  - **Service presets**: pick from a catalog (`https`, `http`, `ssh`, `postgresql`,
    `dns`, …) — friendly path.
  - **Raw port/proto**: e.g. `8443/tcp` for anything not in the catalog.
  - **Source-restricted rich-rules**: e.g. "allow `5432/tcp` only from the eth1 subnet"
    or "only from the tailnet" — expresses the private-vs-public intent directly.
  - Per-zone editing, with **runtime vs permanent** clearly distinguished.
- **Live diff interface:** before applying, show a structured diff (added/removed
  services, ports, rich-rules, zone/interface bindings) — current vs proposed.
- **Auto-rollback safety:**
  1. Snapshot current ruleset to SQLite (and a remote temp backup).
  2. Apply proposed rules.
  3. Start a **rollback timer** (`rollback_timer_secs`, default 60s). The dashboard shows
     a live countdown.
  4. Operator must **confirm "I'm still connected / keep changes."** If the timer expires
     without confirmation (or connectivity is lost), the host **auto-restores** the prior
     ruleset. Implemented host-side via a scheduled revert (e.g. `at`/systemd-run
     one-shot or a backgrounded guarded script) so it fires even if the SSH session dies.
- Editing honors safe-mode (blocked when global `read_only`) and is tiered as a mutation.

### 6.3 Security audit — external-exposure focused
Per host, computes "are we safe from the outside":
- **Reachability:** listening sockets (`ss -tulpen`) cross-referenced against firewall
  zones + interface roles → "what is actually reachable on the **public** interface."
- **SSH hardening:** `PermitRootLogin`, `PasswordAuthentication`, key-only, port, etc.
  (note: Tailscale SSH intercepts; flag if public-interface OpenSSH is also exposed).
- **SELinux:** enforcing / permissive / disabled.
- **Intrusion prevention:** presence/health of fail2ban / CrowdSec.
- **Pending security errata:** count + max severity (see 6.6).
- **Docker exposure:** containers publishing ports to `0.0.0.0` on the public interface.
- Findings are scored/severity-tagged and aggregated into a **fleet security posture**
  summary on the landing page.

### 6.4 Docker / Coolify
- **Container inventory:** `docker ps` + `inspect` → status, image (tag + digest),
  published ports (and which interface/`0.0.0.0`), restart policy, health, mounts.
- **Coolify (disk/Docker-level, no API):** discover Coolify-managed stacks by reading
  their compose files/labels and containers over SSH; group containers by stack/project;
  works across the main instance and child servers. No Coolify token required.
- **Compose stacks:** detect and list compose projects generally (Coolify and non-Coolify).
- **Actions (confirmed, tiered):** restart / redeploy a container or stack. Destructive
  ops (stop, `prune`) require extra confirmation. **Dozzle** containers appear in the
  normal inventory with no special handling/deep-link.
- **Docker daemon config (advisory only):** read `/etc/docker/daemon.json`, compare to a
  documented best-practice baseline (live-restore, json-file log rotation
  `max-size`/`max-file`, `no-new-privileges`, `userland-proxy` off, sane defaults), and
  **flag deviations with explanations**. Cerebro does **not** write daemon.json — it
  shows you exactly what to change and why.

### 6.5 Cron / scheduled jobs
- **Scope:** classic crontabs only — per-user crontabs (`crontab -l -u <user>`),
  `/etc/crontab`, `/etc/cron.d/*`. **systemd timers are out of scope for v1.**
- Unified per-host listing (user, schedule, command, source file).
- **Editable** (add / edit / disable) from the dashboard, behind confirm + safe-mode +
  audit-log; backed up before modification.

### 6.6 Updates — OS errata + Docker images
- **OS:** `dnf updateinfo` / `dnf check-update` → available updates, with **security
  errata (RHSA/RLSA) classified by severity** (Critical/Important/…).
- **Docker images:** compare running container image **digests** vs the registry's
  current tag digest → flag stale/pinned images that have newer builds.
- **Guided, reboot-aware apply:**
  - Applying is **explicit and confirmed**, orchestrated **serially** (canary).
  - Detects whether a reboot is required (`needs-restarting -r`) and surfaces it; reboot
    itself is a separate explicit action, never automatic.
  - Honors safe-mode/global read-only. **No auto-patching** in v1.

### 6.7 Tailscale (read-only)
- Per host via `tailscale status --json`: version, online state, advertised
  routes/exit-node, and the **needs-reauth** flag (ties into 4.3).
- Read-only — managing Tailscale stays with Tailscale's own tooling.

### 6.8 Snapshots & drift
- Periodic **config snapshots** stored in SQLite: firewall ruleset, daemon.json, cron,
  installed/important packages, listening sockets.
- Dashboard **highlights drift** = what changed on each host since the last snapshot. No
  declared-intent baseline required (that's a future option). Snapshots also serve as
  rollback references.

### 6.9 Centralized config view
- The "single place to view configuration" promise: one screen aggregating, across all
  hosts, the security-relevant config (firewall posture, exposure, Docker, cron, updates,
  Tailscale), filterable by group, with drift and security badges.

---

## 7. Safety Model

Layered, since these are production systems:

1. **Action tiering.** Every operation is classified `read` | `safe-write` | `destructive`.
   - `read`: never gated.
   - `safe-write`: shows a diff, requires confirm.
   - `destructive` (rule deletes, container stop, `prune`, package removal): requires
     **extra** confirmation.
2. **Dry-run.** Global `--dry-run` (and UI toggle) computes and shows the diff/plan for any
   mutation **without executing**.
3. **Global read-only switch.** `settings.read_only = true` (or `--read-only`) blocks **all**
   writes fleet-wide; the UI renders action buttons disabled with a clear banner.
4. **Firewall auto-rollback timer.** As in 6.2 — the backstop against SSH lockout.
5. **Append-only audit log.** Every mutation recorded to SQLite: timestamp, host, operator
   context, command(s), the diff applied, result, and rollback reference. Viewable +
   exportable in the dashboard.
6. **Backups before mutation.** Firewall rulesets, daemon.json (advisory), and crontabs are
   snapshotted before any change, enabling restore.

---

## 8. Web Dashboard UX (page map)

- **Fleet overview** — host grid + posture summary + drift/needs-reauth badges + global
  read-only toggle + safe-mode/dry-run indicators.
- **Host detail** — tabs: Overview · Firewall · Security audit · Docker/Coolify · Cron ·
  Updates · Tailscale · Snapshots/Drift · Audit log.
- **Firewall editor** — zone columns (public/internal/tailnet), preset + raw + rich-rule
  controls, live diff pane, apply → rollback countdown + "keep changes" confirm.
- **Updates** — fleet table of pending updates/security errata + reboot-required flags +
  guided apply.
- **Audit log** — searchable history of all changes.
- Persistent **"localhost control plane — do not expose"** banner.

---

## 9. CLI Surface

Primary entry is the dashboard, but a scriptable, composable CLI mirrors core reads (and
gated writes) with `--json` for piping:

```
cerebro serve [--port N] [--no-open]      # start dashboard + open browser
cerebro config validate                   # lint cerebro.toml
cerebro hosts                             # list inventory + health
cerebro host <name>                        # facts for one host
cerebro audit [--group G] [--json]         # external-exposure audit
cerebro fw status [--host H] [--json]      # firewall posture
cerebro fw diff   <host> <plan-file>       # show diff for a proposed change
cerebro fw apply  <host> <plan-file>       # diff + confirm + auto-rollback
cerebro updates [--security-only] [--json] # pending OS errata + stale images
cerebro updates apply --host H [--reboot]  # guided, reboot-aware apply
cerebro docker ps [--host H] [--json]
cerebro cron list [--host H] [--json]
cerebro tailscale status [--json]
cerebro snapshot [--host H]                # take snapshot now
cerebro drift [--host H]                    # show drift since last snapshot
cerebro db migrate                          # housekeeping

# Global flags: --read-only, --dry-run, --config <path>, --parallel
```

---

## 10. Security Considerations

- **Control-plane sensitivity.** The dashboard can edit firewalls and run root commands.
  Mitigations: loopback-only bind, no remote exposure recommended, the warning banner, and
  the safe-mode layers above.
- **Command injection.** All remote commands go through the central command-builder with
  strict argument quoting; no untrusted string interpolation into shell.
- **Secrets.** None required by design — Tailscale SSH handles auth, no Coolify API token,
  no stored passwords. SQLite holds config snapshots/audit only (no credentials).
- **Lockout prevention.** Firewall auto-rollback + connectivity re-confirmation.
- **Least surprise on prod.** Serial/canary applies, destructive-tier confirmations, global
  read-only.

---

## 11. Tech Stack

| Concern | Choice |
|---------|--------|
| Language | Rust (stable, edition 2021/2024) |
| Async runtime | tokio |
| Web framework | axum + tower |
| Live updates | WebSocket or SSE (axum) |
| Templating | minijinja (or askama) — SSR |
| Frontend interactivity | htmx + Alpine.js (vendored static assets) |
| Asset embedding | rust-embed |
| CLI parsing | clap (derive) |
| SSH | shell out to system `ssh` via tokio::process; ControlMaster multiplexing |
| Storage | SQLite via `rusqlite` (or `sqlx`), embedded migrations |
| Serialization | serde / serde_json / toml |
| Diffing | `similar` (text/structured diff rendering) |
| Errors | anyhow (app) + thiserror (library) |
| Logging | tracing + tracing-subscriber |

---

## 12. Suggested Project Layout

```
cerebro/
├── Cargo.toml
├── SPEC.md
├── src/
│   ├── main.rs                # clap dispatch: serve | headless subcommands
│   ├── config.rs              # cerebro.toml load + validate
│   ├── ssh/                   # executor, ControlMaster, command builder, reauth detect
│   ├── backends/
│   │   ├── traits.rs          # PackageManager / Firewall / ServiceManager / ...
│   │   ├── dnf.rs
│   │   ├── firewalld.rs
│   │   ├── systemd.rs
│   │   ├── docker.rs
│   │   └── tailscale.rs
│   ├── engine/
│   │   ├── inventory.rs
│   │   ├── poller.rs          # background poll + cache
│   │   ├── orchestrator.rs    # serial/canary vs parallel apply
│   │   ├── safety.rs          # tiering, dry-run, read-only gate
│   │   ├── snapshots.rs       # snapshot + drift
│   │   └── audit.rs           # append-only audit log
│   ├── features/
│   │   ├── firewall.rs        # editor model, diff, rollback timer
│   │   ├── audit_security.rs  # external-exposure checks
│   │   ├── updates.rs
│   │   ├── cron.rs
│   │   └── docker_view.rs     # incl. Coolify stack discovery
│   ├── web/
│   │   ├── server.rs
│   │   ├── routes/
│   │   ├── ws.rs              # live push
│   │   └── templates/         # embedded
│   ├── db/                    # SQLite schema + migrations
│   └── assets/                # htmx, alpine, css (embedded)
└── tests/
```

---

## 13. Data Model (SQLite, sketch)

```sql
hosts(id, name, groups, last_seen, health, reauth_url)
snapshots(id, host_id, taken_at, kind, payload_json)        -- firewall|daemon|cron|packages|sockets
drift(id, host_id, detected_at, kind, summary, diff)
audit_log(id, ts, host_id, action, tier, command, diff, result, rollback_ref)
fw_backups(id, host_id, taken_at, ruleset_blob)
update_cache(id, host_id, checked_at, errata_json, image_staleness_json)
```

---

## 14. Roadmap / Milestones

1. **M1 — Plumbing.** `cerebro.toml` + validation; SSH executor with ControlMaster + reauth
   detection; SQLite + migrations; host facts; `cerebro hosts` / `host`.
2. **M2 — Read-only dashboard.** axum + SSR/htmx; fleet overview + host detail; background
   poller + cache; Tailscale status; container/cron/listening-socket inventory.
3. **M3 — Security audit.** External-exposure checks + posture summary + `cerebro audit`.
4. **M4 — Firewall editor.** Zone model, presets/raw/rich-rules, live diff, **auto-rollback
   timer**, backups. The flagship feature.
5. **M5 — Updates.** OS errata + stale image detection; guided, reboot-aware apply.
6. **M6 — Docker/Coolify actions + daemon.json advisory.** Confirmed restart/redeploy;
   Coolify stack discovery; daemon.json deviation report.
7. **M7 — Snapshots & drift surfacing.** Periodic snapshots + "changed since" highlighting.
8. **M8 — Safety polish & audit log UI.** Tiering, dry-run everywhere, global read-only,
   audit-log viewer; cron editing.

---

## 15. Future / Out of Scope (post-v1 candidates)

- ufw + apt/Debian/Ubuntu backends (the trait abstraction is built for this).
- External alerting (Discord/ntfy/webhook) + scheduled headless `cerebro scan`.
- Declared-intent baselines for stronger drift/compliance enforcement.
- systemd-timer visibility/editing.
- Coolify API integration (richer metadata than disk-level).
- CIS-style full benchmark mode.
- Per-host write policies / role-based locking of prod hosts.
- Optional lightweight agent for continuous telemetry.

---

## 16. Open Questions (to revisit during build)

- Exact host-side mechanism for the firewall rollback timer (`systemd-run --on-active`
  one-shot vs `at` vs guarded background script) — pick the most universally available on
  CentOS Stream 10 / Rocky 10 minimal installs.
- Registry-digest comparison for stale images when private/authenticated registries are in
  play (Coolify often uses these) — may need per-registry handling.
- Default poll interval vs SSH load at fleet scale; per-host override may be warranted.
- Whether "internal" (eth1) zone should default to `internal` vs a custom restricted zone.
