//! Cerebro command-line entrypoint.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};

use cerebro::cli::{self, Command, ConfigCommand, FwCommand};
use cerebro::config::Config;
use cerebro::db::{NewSnapshot, Store};
use cerebro::engine::{drift, inventory};
use cerebro::model::{HostView, SnapshotKind};
use cerebro::ssh::{CommandRunner, SshRunner};
use cerebro::web::{self, AppState};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = cli::parse();
    let config_path = cli.config.clone().unwrap_or_else(default_config_path);

    match cli.command {
        Command::Serve { port, no_open } => serve(&config_path, cli.read_only, port, no_open).await,
        Command::Config { cmd } => match cmd {
            ConfigCommand::Validate => {
                Config::load(&config_path)?;
                println!("{}: valid", config_path.display());
                Ok(())
            }
        },
        Command::Hosts => {
            print_hosts(&load_and_gather(&config_path).await?);
            Ok(())
        }
        Command::Host { name } => {
            let fleet = load_and_gather(&config_path).await?;
            print_host(&fleet, &name)
        }
        Command::Audit { group, json } => {
            let fleet = load_and_gather(&config_path).await?;
            print_audit(&fleet, group.as_deref(), json)
        }
        Command::Updates {
            security_only,
            json,
        } => {
            let fleet = load_and_gather(&config_path).await?;
            print_updates(&fleet, security_only, json)
        }
        Command::Fw { cmd } => match cmd {
            FwCommand::Status { host, json } => {
                let fleet = load_and_gather(&config_path).await?;
                print_firewall(&fleet, host.as_deref(), json)
            }
        },
        Command::Docker { host, json } => {
            let fleet = load_and_gather(&config_path).await?;
            print_docker(&fleet, host.as_deref(), json)
        }
        Command::Cron { host, json } => {
            let fleet = load_and_gather(&config_path).await?;
            print_cron(&fleet, host.as_deref(), json)
        }
        Command::Tailscale { json } => {
            let fleet = load_and_gather(&config_path).await?;
            print_tailscale(&fleet, json)
        }
        Command::Snapshot { host } => snapshot(&config_path, host.as_deref()).await,
        Command::Drift { host } => show_drift(&config_path, host.as_deref()).await,
    }
}

fn default_config_path() -> PathBuf {
    if let Ok(p) = std::env::var("CEREBRO_CONFIG") {
        return PathBuf::from(p);
    }
    config_base().join("cerebro").join("cerebro.toml")
}

fn config_base() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME").map_or_else(|_| home_dir().join(".config"), PathBuf::from)
}

fn db_path() -> PathBuf {
    let base = std::env::var("XDG_DATA_HOME")
        .map_or_else(|_| home_dir().join(".local").join("share"), PathBuf::from);
    base.join("cerebro").join("cerebro.db")
}

fn home_dir() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()))
}

fn new_runner() -> Arc<dyn CommandRunner> {
    Arc::new(SshRunner::new())
}

async fn load_and_gather(path: &Path) -> Result<Vec<HostView>> {
    let config = Config::load(path)?;
    Ok(inventory::gather_fleet(new_runner(), &config).await)
}

fn open_store() -> Result<Store> {
    let path = db_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(Store::open(&path)?)
}

async fn serve(path: &Path, read_only_flag: bool, port: Option<u16>, no_open: bool) -> Result<()> {
    let config = Config::load(path)?;
    let read_only = read_only_flag || config.settings.read_only;
    let port = port.unwrap_or(config.settings.bind_port);
    let runner = new_runner();

    println!("Gathering initial fleet state…");
    let initial = inventory::gather_fleet(Arc::clone(&runner), &config).await;
    let state = AppState::new(initial, read_only);

    let poll_state = state.clone();
    let poll_runner = Arc::clone(&runner);
    let poll_config = config.clone();
    tokio::spawn(async move { poll_loop(poll_state, poll_runner, poll_config).await });

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let url = format!("http://127.0.0.1:{port}");
    println!(
        "Cerebro dashboard: {url}  (localhost only — do not expose){}",
        if read_only { "  [READ-ONLY]" } else { "" }
    );
    if !no_open {
        let _ = open::that(&url);
    }
    axum::serve(listener, web::router(state)).await?;
    Ok(())
}

async fn poll_loop(state: AppState, runner: Arc<dyn CommandRunner>, config: Config) {
    let interval = Duration::from_secs(config.settings.poll_interval_secs.max(5));
    loop {
        tokio::time::sleep(interval).await;
        let fleet = inventory::gather_fleet(Arc::clone(&runner), &config).await;
        *state.fleet.write().await = fleet;
        tracing::debug!("fleet refreshed");
    }
}

async fn snapshot(path: &Path, only: Option<&str>) -> Result<()> {
    let fleet = load_and_gather(path).await?;
    let store = open_store()?;
    for view in &fleet {
        if only.is_some_and(|name| view.name != name) {
            continue;
        }
        if let Some(firewall) = &view.firewall {
            let payload = serde_json::to_string_pretty(firewall)?;
            store.save_snapshot(&NewSnapshot {
                host: view.name.clone(),
                kind: SnapshotKind::Firewall,
                payload,
            })?;
            println!("snapshot saved: {} firewall", view.name);
        }
    }
    Ok(())
}

async fn show_drift(path: &Path, only: Option<&str>) -> Result<()> {
    let fleet = load_and_gather(path).await?;
    let store = open_store()?;
    for view in &fleet {
        if only.is_some_and(|name| view.name != name) {
            continue;
        }
        let Some(firewall) = &view.firewall else {
            continue;
        };
        let current = serde_json::to_string_pretty(firewall)?;
        match store.latest_snapshot(&view.name, SnapshotKind::Firewall)? {
            Some(prev) => match drift::diff_snapshots(
                SnapshotKind::Firewall,
                &view.name,
                &prev.payload,
                &current,
            ) {
                Some(d) => {
                    println!("DRIFT {} firewall: {}", view.name, d.summary);
                    println!("{}", d.diff);
                }
                None => println!("{}: no firewall drift", view.name),
            },
            None => println!("{}: no prior snapshot", view.name),
        }
    }
    Ok(())
}

fn matches_group(view: &HostView, group: Option<&str>) -> bool {
    group.is_none_or(|g| view.groups.iter().any(|h| h == g))
}

fn print_hosts(fleet: &[HostView]) {
    println!(
        "{:<22} {:<12} {:<24} {:>6} {:>9}",
        "HOST", "HEALTH", "GROUPS", "SEC-UP", "MAX-SEV"
    );
    for view in fleet {
        let health = format!("{:?}", view.health);
        let groups = view.groups.join(",");
        let sev = view
            .audit
            .as_ref()
            .map_or_else(|| "-".to_string(), |a| a.max_severity().to_string());
        println!(
            "{:<22} {health:<12} {groups:<24} {:>6} {sev:>9}",
            view.name,
            view.security_update_count()
        );
    }
}

fn find_host<'a>(fleet: &'a [HostView], name: &str) -> Result<&'a HostView> {
    match fleet.iter().find(|v| v.name == name) {
        Some(v) => Ok(v),
        None => bail!("unknown host: {name}"),
    }
}

fn print_host(fleet: &[HostView], name: &str) -> Result<()> {
    let view = find_host(fleet, name)?;
    println!("# {} ({:?})", view.name, view.health);
    if let Some(url) = &view.auth_url {
        println!("  Tailscale re-auth required: {url}");
    }
    if let Some(facts) = &view.facts {
        let pretty = facts.os.pretty_name.as_deref().unwrap_or(&facts.os.id);
        println!(
            "  os: {pretty}  kernel: {}  selinux: {:?}",
            facts.kernel, facts.selinux
        );
    }
    println!(
        "  containers: {}  cron jobs: {}  security updates: {}",
        view.containers.len(),
        view.cron.len(),
        view.security_update_count()
    );
    if let Some(audit) = &view.audit {
        println!(
            "  findings: {} (max severity {})",
            audit.findings.len(),
            audit.max_severity()
        );
        for finding in &audit.findings {
            println!(
                "    [{}] {} — {}",
                finding.severity, finding.title, finding.detail
            );
        }
    }
    Ok(())
}

fn print_audit(fleet: &[HostView], group: Option<&str>, json: bool) -> Result<()> {
    let reports: Vec<_> = fleet
        .iter()
        .filter(|v| matches_group(v, group))
        .filter_map(|v| v.audit.as_ref())
        .collect();
    if json {
        println!("{}", serde_json::to_string_pretty(&reports)?);
        return Ok(());
    }
    for report in reports {
        println!("# {} (max severity {})", report.host, report.max_severity());
        for finding in &report.findings {
            println!(
                "  [{}] {} — {}",
                finding.severity, finding.title, finding.detail
            );
        }
    }
    Ok(())
}

fn print_updates(fleet: &[HostView], security_only: bool, json: bool) -> Result<()> {
    if json {
        let data: Vec<_> = fleet
            .iter()
            .map(|v| {
                let updates: Vec<_> = v
                    .updates
                    .iter()
                    .filter(|u| !security_only || u.is_security())
                    .collect();
                serde_json::json!({ "host": v.name, "updates": updates })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }
    for view in fleet {
        let updates: Vec<_> = view
            .updates
            .iter()
            .filter(|u| !security_only || u.is_security())
            .collect();
        if updates.is_empty() {
            continue;
        }
        println!("# {} ({} updates)", view.name, updates.len());
        for u in updates {
            let sev = u
                .errata
                .as_ref()
                .map_or_else(String::new, |e| format!(" [{}]", e.severity));
            println!(
                "  {} {} -> {}{sev}",
                u.name,
                u.current_version.as_deref().unwrap_or("?"),
                u.new_version
            );
        }
    }
    Ok(())
}

fn print_firewall(fleet: &[HostView], host: Option<&str>, json: bool) -> Result<()> {
    let selected: Vec<_> = fleet
        .iter()
        .filter(|v| host.is_none_or(|h| v.name == h))
        .collect();
    if json {
        let data: Vec<_> = selected
            .iter()
            .map(|v| serde_json::json!({ "host": v.name, "firewall": v.firewall }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }
    for view in selected {
        println!("# {}", view.name);
        let Some(fw) = &view.firewall else {
            println!("  (no firewall data)");
            continue;
        };
        for zone in &fw.zones {
            let ports: Vec<String> = zone.ports.iter().map(ToString::to_string).collect();
            println!(
                "  zone {} [{}]  services: {}  ports: {}",
                zone.name,
                zone.interfaces.join(","),
                zone.services.join(" "),
                ports.join(" ")
            );
        }
    }
    Ok(())
}

fn print_docker(fleet: &[HostView], host: Option<&str>, json: bool) -> Result<()> {
    let selected: Vec<_> = fleet
        .iter()
        .filter(|v| host.is_none_or(|h| v.name == h))
        .collect();
    if json {
        let data: Vec<_> = selected
            .iter()
            .map(|v| serde_json::json!({ "host": v.name, "containers": v.containers }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }
    for view in selected {
        println!("# {}", view.name);
        for c in &view.containers {
            let exposed = if c.is_publicly_exposed() {
                "  ⚠ public"
            } else {
                ""
            };
            println!("  {} [{}] {}{exposed}", c.name, c.state, c.image);
        }
    }
    Ok(())
}

fn print_cron(fleet: &[HostView], host: Option<&str>, json: bool) -> Result<()> {
    let selected: Vec<_> = fleet
        .iter()
        .filter(|v| host.is_none_or(|h| v.name == h))
        .collect();
    if json {
        let data: Vec<_> = selected
            .iter()
            .map(|v| serde_json::json!({ "host": v.name, "cron": v.cron }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }
    for view in selected {
        println!("# {}", view.name);
        for job in &view.cron {
            let state = if job.enabled { "" } else { " (disabled)" };
            println!("  {} {}{state}", job.schedule, job.command);
        }
    }
    Ok(())
}

fn print_tailscale(fleet: &[HostView], json: bool) -> Result<()> {
    if json {
        let data: Vec<_> = fleet
            .iter()
            .map(|v| serde_json::json!({ "host": v.name, "tailscale": v.tailscale }))
            .collect();
        println!("{}", serde_json::to_string_pretty(&data)?);
        return Ok(());
    }
    for view in fleet {
        match &view.tailscale {
            Some(ts) => println!(
                "{:<22} online={} reauth={} version={}",
                view.name,
                ts.online,
                ts.needs_reauth,
                ts.version.as_deref().unwrap_or("?")
            ),
            None => println!("{:<22} (no tailscale data)", view.name),
        }
    }
    Ok(())
}
