//! Shared domain model for Cerebro.
//!
//! Every backend parser, the engine, the web layer and the CLI speak in terms of
//! these types. Keeping them in one place is what lets the rest of the codebase be
//! implemented as independent, pure units.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// System facts
// ---------------------------------------------------------------------------

/// Linux distribution family, detected from `/etc/os-release`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Distro {
    CentosStream,
    Rocky,
    Rhel,
    Fedora,
    AlmaLinux,
    Debian,
    Ubuntu,
    Other(String),
}

impl Distro {
    /// Map an `/etc/os-release` `ID=` value onto a known family.
    pub fn from_id(id: &str) -> Self {
        match id.trim().trim_matches('"').to_ascii_lowercase().as_str() {
            "centos" => Self::CentosStream,
            "rocky" => Self::Rocky,
            "rhel" => Self::Rhel,
            "fedora" => Self::Fedora,
            "almalinux" => Self::AlmaLinux,
            "debian" => Self::Debian,
            "ubuntu" => Self::Ubuntu,
            other => Self::Other(other.to_string()),
        }
    }

    /// Whether this distro uses the `dnf`/`rpm` package ecosystem.
    pub fn is_rpm(&self) -> bool {
        matches!(
            self,
            Self::CentosStream | Self::Rocky | Self::Rhel | Self::Fedora | Self::AlmaLinux
        )
    }
}

/// Parsed subset of `/etc/os-release`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsRelease {
    pub id: String,
    pub version_id: Option<String>,
    pub pretty_name: Option<String>,
    pub distro: Distro,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelinuxMode {
    Enforcing,
    Permissive,
    Disabled,
    #[default]
    Unknown,
}

/// Liveness of a host as Cerebro currently understands it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostHealth {
    Online,
    NeedsReauth,
    Unreachable,
    #[default]
    Unknown,
}

/// The role an operator has assigned to a network interface in `cerebro.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceRole {
    Public,
    Private,
    Tailnet,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetInterface {
    pub name: String,
    pub role: InterfaceRole,
    pub addresses: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Facts {
    pub os: OsRelease,
    pub kernel: String,
    pub selinux: SelinuxMode,
    pub uptime_secs: Option<u64>,
    pub interfaces: Vec<NetInterface>,
}

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallBackend {
    #[default]
    Firewalld,
    Ufw,
    Nftables,
    Unknown,
}

/// A single `port/proto` opening (the port may be a range such as `8000-8100`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortRule {
    pub port: String,
    pub protocol: Protocol,
}

impl std::fmt::Display for PortRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.port, self.protocol)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FirewallZone {
    pub name: String,
    pub interfaces: Vec<String>,
    pub sources: Vec<String>,
    pub services: Vec<String>,
    pub ports: Vec<PortRule>,
    pub rich_rules: Vec<String>,
    pub target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallState {
    pub backend: FirewallBackend,
    pub zones: Vec<FirewallZone>,
}

impl FirewallState {
    pub fn zone(&self, name: &str) -> Option<&FirewallZone> {
        self.zones.iter().find(|z| z.name == name)
    }
}

/// The difference between the current and desired state of a single zone.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ZoneDiff {
    pub zone: String,
    pub added_services: Vec<String>,
    pub removed_services: Vec<String>,
    pub added_ports: Vec<PortRule>,
    pub removed_ports: Vec<PortRule>,
    pub added_rich_rules: Vec<String>,
    pub removed_rich_rules: Vec<String>,
}

impl ZoneDiff {
    pub fn is_empty(&self) -> bool {
        self.added_services.is_empty()
            && self.removed_services.is_empty()
            && self.added_ports.is_empty()
            && self.removed_ports.is_empty()
            && self.added_rich_rules.is_empty()
            && self.removed_rich_rules.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Updates / errata
// ---------------------------------------------------------------------------

/// Update severity, ordered so that `max()` yields the most urgent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    #[default]
    Unknown,
    Low,
    Moderate,
    Important,
    Critical,
}

impl Severity {
    /// The most urgent severity in an iterator, or [`Severity::Unknown`] if empty.
    pub fn max_of<I: IntoIterator<Item = Self>>(items: I) -> Self {
        items.into_iter().max().unwrap_or(Self::Unknown)
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Unknown => "unknown",
            Self::Low => "low",
            Self::Moderate => "moderate",
            Self::Important => "important",
            Self::Critical => "critical",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrataKind {
    Security,
    BugFix,
    Enhancement,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Errata {
    pub advisory: String,
    pub severity: Severity,
    pub kind: ErrataKind,
}

/// A pending package update, optionally annotated with its security errata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsUpdate {
    pub name: String,
    pub arch: Option<String>,
    pub current_version: Option<String>,
    pub new_version: String,
    pub repo: Option<String>,
    pub errata: Option<Errata>,
}

impl OsUpdate {
    pub fn is_security(&self) -> bool {
        matches!(&self.errata, Some(e) if e.kind == ErrataKind::Security)
    }
}

// ---------------------------------------------------------------------------
// Docker / containers
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapping {
    pub host_ip: Option<String>,
    pub host_port: Option<String>,
    pub container_port: String,
    pub protocol: Protocol,
}

impl PortMapping {
    /// Whether this mapping binds a host port on a wildcard (internet-facing) address.
    pub fn publicly_exposed(&self) -> bool {
        matches!(
            self.host_ip.as_deref(),
            Some("0.0.0.0" | "::" | "::0" | "*")
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    pub image_digest: Option<String>,
    pub state: String,
    pub status: String,
    pub ports: Vec<PortMapping>,
    pub restart_policy: Option<String>,
    pub health: Option<String>,
    pub compose_project: Option<String>,
}

impl Container {
    pub fn is_publicly_exposed(&self) -> bool {
        self.ports.iter().any(PortMapping::publicly_exposed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageStaleness {
    pub container: String,
    pub image: String,
    pub running_digest: Option<String>,
    pub registry_digest: Option<String>,
}

impl ImageStaleness {
    pub fn is_stale(&self) -> bool {
        match (&self.running_digest, &self.registry_digest) {
            (Some(a), Some(b)) => a != b,
            _ => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Cron
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "path")]
pub enum CronSource {
    UserCrontab,
    EtcCrontab,
    CronD(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CronJob {
    pub source: CronSource,
    pub user: Option<String>,
    pub schedule: String,
    pub command: String,
    pub raw: String,
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Listening sockets
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListeningSocket {
    pub protocol: Protocol,
    pub local_addr: String,
    pub local_port: u16,
    pub process: Option<String>,
    pub pid: Option<u32>,
}

impl ListeningSocket {
    /// Whether this socket is bound to a wildcard address (all interfaces).
    pub fn is_wildcard(&self) -> bool {
        matches!(
            self.local_addr.as_str(),
            "0.0.0.0" | "*" | "::" | "[::]" | "::0"
        )
    }
}

// ---------------------------------------------------------------------------
// Tailscale (read-only)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TailscaleStatus {
    pub version: Option<String>,
    pub backend_state: Option<String>,
    pub online: bool,
    pub needs_reauth: bool,
    pub auth_url: Option<String>,
    pub hostname: Option<String>,
    pub addresses: Vec<String>,
    pub routes: Vec<String>,
    pub exit_node: bool,
}

// ---------------------------------------------------------------------------
// sshd hardening
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SshdConfig {
    pub permit_root_login: Option<String>,
    pub password_authentication: Option<bool>,
    pub pubkey_authentication: Option<bool>,
    pub port: Option<u16>,
}

// ---------------------------------------------------------------------------
// Security audit
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    Exposure,
    Ssh,
    Selinux,
    Ips,
    Errata,
    Docker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub category: FindingCategory,
    pub detail: String,
    pub recommendation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditReport {
    pub host: String,
    pub findings: Vec<Finding>,
}

impl AuditReport {
    pub fn max_severity(&self) -> Severity {
        Severity::max_of(self.findings.iter().map(|f| f.severity))
    }

    pub fn count_at_least(&self, sev: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity >= sev).count()
    }
}

// ---------------------------------------------------------------------------
// Safety / audit log
// ---------------------------------------------------------------------------

/// How dangerous an operation is, used by the safety gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionTier {
    Read,
    SafeWrite,
    Destructive,
}

impl std::fmt::Display for ActionTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Read => "read",
            Self::SafeWrite => "safe-write",
            Self::Destructive => "destructive",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: DateTime<Utc>,
    pub host: String,
    pub action: String,
    pub tier: ActionTier,
    pub command: String,
    pub diff: Option<String>,
    pub result: String,
}

// ---------------------------------------------------------------------------
// Snapshots / drift
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    Firewall,
    DockerDaemon,
    Cron,
    Packages,
    Sockets,
}

impl std::fmt::Display for SnapshotKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Firewall => "firewall",
            Self::DockerDaemon => "docker_daemon",
            Self::Cron => "cron",
            Self::Packages => "packages",
            Self::Sockets => "sockets",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: i64,
    pub host: String,
    pub taken_at: DateTime<Utc>,
    pub kind: SnapshotKind,
    pub payload: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Drift {
    pub host: String,
    pub kind: SnapshotKind,
    pub summary: String,
    pub diff: String,
}

// ---------------------------------------------------------------------------
// Aggregated per-host view (the dashboard cache unit)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HostView {
    pub name: String,
    pub groups: Vec<String>,
    pub health: HostHealth,
    pub auth_url: Option<String>,
    pub error: Option<String>,
    pub facts: Option<Facts>,
    pub firewall: Option<FirewallState>,
    pub tailscale: Option<TailscaleStatus>,
    pub containers: Vec<Container>,
    pub cron: Vec<CronJob>,
    pub updates: Vec<OsUpdate>,
    pub sockets: Vec<ListeningSocket>,
    pub audit: Option<AuditReport>,
    pub last_polled: Option<DateTime<Utc>>,
}

impl HostView {
    pub fn new(name: impl Into<String>, groups: Vec<String>) -> Self {
        Self {
            name: name.into(),
            groups,
            ..Self::default()
        }
    }

    pub fn security_update_count(&self) -> usize {
        self.updates.iter().filter(|u| u.is_security()).count()
    }
}
