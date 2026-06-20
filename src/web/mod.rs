//! Server-rendered local dashboard.
//!
//! A single-binary axum 0.8 application that renders the in-memory fleet cache as
//! plain HTML via minijinja. Everything is intentionally local-only: the templates
//! carry a persistent "do not expose" banner and an optional read-only badge so an
//! operator can never mistake this for a hardened, internet-facing control plane.

use std::sync::{Arc, OnceLock};

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;
use chrono::{DateTime, Utc};
use minijinja::{context, Environment};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::model::{Finding, FirewallState, HostView, Severity};

/// Shared application state handed to every request handler.
#[derive(Clone)]
pub struct AppState {
    /// The fleet cache, refreshed out of band by the polling engine.
    pub fleet: Arc<RwLock<Vec<HostView>>>,
    /// When true, the UI advertises that no mutating actions are permitted.
    pub read_only: bool,
}

impl AppState {
    pub fn new(hosts: Vec<HostView>, read_only: bool) -> Self {
        Self {
            fleet: Arc::new(RwLock::new(hosts)),
            read_only,
        }
    }
}

/// A breakdown of findings by severity, used wherever the UI shows a "risk" summary.
#[derive(Serialize, Default, Clone, Copy)]
struct SeverityCounts {
    critical: usize,
    important: usize,
    moderate: usize,
    low: usize,
    unknown: usize,
    total: usize,
}

impl SeverityCounts {
    fn from_severities(severities: impl IntoIterator<Item = Severity>) -> Self {
        let mut c = Self::default();
        for severity in severities {
            match severity {
                Severity::Critical => c.critical += 1,
                Severity::Important => c.important += 1,
                Severity::Moderate => c.moderate += 1,
                Severity::Low => c.low += 1,
                Severity::Unknown => c.unknown += 1,
            }
            c.total += 1;
        }
        c
    }

    fn from_findings(findings: &[Finding]) -> Self {
        Self::from_severities(findings.iter().map(|f| f.severity))
    }

    fn add(&mut self, other: &Self) {
        self.critical += other.critical;
        self.important += other.important;
        self.moderate += other.moderate;
        self.low += other.low;
        self.unknown += other.unknown;
        self.total += other.total;
    }
}

/// One card on the fleet landing page.
#[derive(Serialize)]
struct HostSummary {
    name: String,
    groups: Vec<String>,
    health: crate::model::HostHealth,
    security_update_count: usize,
    severity: SeverityCounts,
    container_count: usize,
    last_polled: Option<String>,
}

impl HostSummary {
    fn from_host(host: &HostView) -> Self {
        let findings = host.audit.as_ref().map(|a| a.findings.as_slice());
        Self {
            name: host.name.clone(),
            groups: host.groups.clone(),
            health: host.health,
            security_update_count: host.security_update_count(),
            severity: findings
                .map(SeverityCounts::from_findings)
                .unwrap_or_default(),
            container_count: host.containers.len(),
            last_polled: host.last_polled.map(rel_time),
        }
    }
}

/// Fleet-wide totals shown in the header strip above the host cards.
#[derive(Serialize, Default)]
struct FleetSummary {
    total: usize,
    online: usize,
    needs_reauth: usize,
    unreachable: usize,
    unknown: usize,
    severity: SeverityCounts,
    security_updates: usize,
    containers: usize,
}

impl FleetSummary {
    fn from_hosts(hosts: &[HostView]) -> Self {
        let mut s = Self {
            total: hosts.len(),
            ..Self::default()
        };
        for host in hosts {
            match host.health {
                crate::model::HostHealth::Online => s.online += 1,
                crate::model::HostHealth::NeedsReauth => s.needs_reauth += 1,
                crate::model::HostHealth::Unreachable => s.unreachable += 1,
                crate::model::HostHealth::Unknown => s.unknown += 1,
            }
            if let Some(audit) = &host.audit {
                s.severity
                    .add(&SeverityCounts::from_findings(&audit.findings));
            }
            s.security_updates += host.security_update_count();
            s.containers += host.containers.len();
        }
        s
    }
}

/// At-a-glance counters rendered on a host's Overview tab.
#[derive(Serialize)]
struct HostStats {
    severity: SeverityCounts,
    containers_total: usize,
    containers_running: usize,
    containers_exposed: usize,
    security_updates: usize,
    updates_total: usize,
    cron_total: usize,
    socket_total: usize,
    wildcard_sockets: usize,
    os: Option<String>,
    uptime: Option<String>,
}

impl HostStats {
    fn from_host(host: &HostView) -> Self {
        let findings = host
            .audit
            .as_ref()
            .map_or(&[][..], |a| a.findings.as_slice());
        Self {
            severity: SeverityCounts::from_findings(findings),
            containers_total: host.containers.len(),
            containers_running: host
                .containers
                .iter()
                .filter(|c| c.state.eq_ignore_ascii_case("running"))
                .count(),
            containers_exposed: host
                .containers
                .iter()
                .filter(|c| c.is_publicly_exposed())
                .count(),
            security_updates: host.security_update_count(),
            updates_total: host.updates.len(),
            cron_total: host.cron.len(),
            socket_total: host.sockets.len(),
            wildcard_sockets: host.sockets.iter().filter(|s| s.is_wildcard()).count(),
            os: host
                .facts
                .as_ref()
                .map(|f| f.os.pretty_name.clone().unwrap_or_else(|| f.os.id.clone())),
            uptime: host
                .facts
                .as_ref()
                .and_then(|f| f.uptime_secs)
                .map(fmt_uptime),
        }
    }
}

/// A single opening in a firewall zone, rendered as a friendly chip.
#[derive(Serialize)]
struct Opening {
    label: String,
    detail: String,
}

/// A firewall zone translated into plain language for the Firewall tab.
#[derive(Serialize)]
struct ZoneView {
    name: String,
    default_policy: String,
    permissive: bool,
    applies_to: Vec<String>,
    openings: Vec<Opening>,
    rich_rules: Vec<String>,
}

/// The whole firewall, restated so an operator can read it without knowing firewalld.
#[derive(Serialize)]
struct FirewallView {
    backend: String,
    zones: Vec<ZoneView>,
}

impl FirewallView {
    fn from_state(state: &FirewallState) -> Self {
        let zones = state
            .zones
            .iter()
            .map(|zone| {
                let mut applies_to: Vec<String> = Vec::new();
                applies_to.extend(zone.interfaces.iter().map(|i| format!("interface {i}")));
                applies_to.extend(zone.sources.iter().map(|s| format!("source {s}")));

                let mut openings: Vec<Opening> = Vec::new();
                for service in &zone.services {
                    openings.push(Opening {
                        label: service_label(service).to_string(),
                        detail: service.clone(),
                    });
                }
                for port in &zone.ports {
                    let endpoint = format!("{}/{}", port.port, port.protocol);
                    openings.push(Opening {
                        label: port_label(&port.port).unwrap_or("Port").to_string(),
                        detail: endpoint,
                    });
                }

                ZoneView {
                    name: zone.name.clone(),
                    default_policy: default_policy(zone.target.as_deref()).to_string(),
                    permissive: matches!(zone.target.as_deref(), Some("ACCEPT")),
                    applies_to,
                    openings,
                    rich_rules: zone.rich_rules.clone(),
                }
            })
            .collect();
        Self {
            backend: format!("{:?}", state.backend).to_lowercase(),
            zones,
        }
    }
}

/// A single finding annotated with the host it came from, for the aggregate page.
#[derive(Serialize)]
struct AuditRow {
    host: String,
    finding: Finding,
}

/// Render a firewalld zone target as a one-line default policy in plain words.
fn default_policy(target: Option<&str>) -> &'static str {
    match target {
        Some("ACCEPT") => "Accepts all inbound traffic",
        Some("DROP") => "Silently drops unmatched traffic",
        Some("%%REJECT%%" | "REJECT") => "Rejects unmatched traffic",
        // firewalld's implicit default is to reject anything not explicitly allowed.
        _ => "Rejects unmatched traffic (default)",
    }
}

/// Friendly display name for a firewalld service identifier.
fn service_label(service: &str) -> &str {
    match service {
        "ssh" => "SSH",
        "http" => "HTTP",
        "https" => "HTTPS",
        "dns" => "DNS",
        "dhcpv6-client" => "DHCPv6",
        "cockpit" => "Cockpit",
        "mysql" => "MySQL",
        "postgresql" => "PostgreSQL",
        "samba" => "Samba",
        "nfs" => "NFS",
        "smtp" => "SMTP",
        "imaps" => "IMAPS",
        "wireguard" => "WireGuard",
        other => other,
    }
}

/// Friendly name for a well-known port number (the input may be a range like `8000-8100`).
fn port_label(port: &str) -> Option<&'static str> {
    let number = port.split('-').next().and_then(|p| p.parse::<u16>().ok())?;
    Some(match number {
        22 => "SSH",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        443 => "HTTPS",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        6379 => "Redis",
        8080 | 8443 => "Web",
        27017 => "MongoDB",
        _ => return None,
    })
}

/// Findings sorted most-urgent first, for the security views.
fn findings_by_severity(host: &HostView) -> Vec<Finding> {
    let mut findings = host
        .audit
        .as_ref()
        .map(|a| a.findings.clone())
        .unwrap_or_default();
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    findings
}

/// A coarse "x minutes ago" rendering of a poll timestamp.
fn rel_time(ts: DateTime<Utc>) -> String {
    let secs = (Utc::now() - ts).num_seconds();
    if secs < 5 {
        return "just now".to_string();
    }
    if secs < 60 {
        return format!("{secs}s ago");
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{mins}m ago");
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{hours}h ago");
    }
    format!("{}d ago", hours / 24)
}

/// Compact uptime such as `3d 4h` or `12m`.
fn fmt_uptime(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let mins = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else if mins > 0 {
        format!("{mins}m")
    } else {
        "<1m".to_string()
    }
}

fn environment() -> &'static Environment<'static> {
    static ENV: OnceLock<Environment<'static>> = OnceLock::new();
    ENV.get_or_init(|| {
        let mut env = Environment::new();
        // Templates are registered without a `.html` suffix, so force HTML escaping
        // explicitly: every `{{ ... }}` is attacker-influenced (container names, cron
        // commands, image tags) and must never be rendered as raw markup.
        env.set_auto_escape_callback(|_| minijinja::AutoEscape::Html);
        env.add_template("base", include_str!("templates/base.html"))
            .expect("base template");
        env.add_template("overview", include_str!("templates/overview.html"))
            .expect("overview template");
        env.add_template("host", include_str!("templates/host.html"))
            .expect("host template");
        env.add_template("audit", include_str!("templates/audit.html"))
            .expect("audit template");
        env
    })
}

fn render(name: &str, ctx: minijinja::Value) -> Html<String> {
    let tmpl = environment()
        .get_template(name)
        .expect("template registered");
    let html = tmpl
        .render(ctx)
        .unwrap_or_else(|e| format!("template error: {e}"));
    Html(html)
}

async fn overview(State(state): State<AppState>) -> Html<String> {
    let fleet = state.fleet.read().await;
    let hosts: Vec<HostSummary> = fleet.iter().map(HostSummary::from_host).collect();
    let summary = FleetSummary::from_hosts(&fleet);
    render(
        "overview",
        context! {
            hosts => hosts,
            summary => summary,
            read_only => state.read_only,
            active => "fleet",
        },
    )
}

async fn host_detail(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> axum::response::Response {
    let fleet = state.fleet.read().await;
    let Some(host) = fleet.iter().find(|h| h.name == name) else {
        return (StatusCode::NOT_FOUND, "unknown host").into_response();
    };
    let findings = findings_by_severity(host);
    let top_findings: Vec<Finding> = findings.iter().take(4).cloned().collect();
    render(
        "host",
        context! {
            host => host,
            stats => HostStats::from_host(host),
            findings => findings,
            top_findings => top_findings,
            firewall_view => host.firewall.as_ref().map(FirewallView::from_state),
            last_polled => host.last_polled.map(rel_time),
            read_only => state.read_only,
            active => "",
        },
    )
    .into_response()
}

async fn audit(State(state): State<AppState>) -> Html<String> {
    let fleet = state.fleet.read().await;
    let mut rows: Vec<AuditRow> = Vec::new();
    for host in &*fleet {
        if let Some(report) = &host.audit {
            for finding in &report.findings {
                rows.push(AuditRow {
                    host: host.name.clone(),
                    finding: finding.clone(),
                });
            }
        }
    }
    rows.sort_by_key(|row| std::cmp::Reverse(row.finding.severity));
    let severity = SeverityCounts::from_severities(rows.iter().map(|r| r.finding.severity));
    render(
        "audit",
        context! {
            rows => rows,
            severity => severity,
            read_only => state.read_only,
            active => "audit",
        },
    )
}

async fn healthz() -> &'static str {
    "ok"
}

async fn style() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css")],
        include_str!("templates/style.css"),
    )
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript")],
        include_str!("templates/app.js"),
    )
}

/// Build the dashboard router with all routes wired to `state`.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(overview))
        .route("/host/{name}", get(host_detail))
        .route("/audit", get(audit))
        .route("/healthz", get(healthz))
        .route("/assets/style.css", get(style))
        .route("/assets/app.js", get(app_js))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::model::{AuditReport, Container, Finding, FindingCategory, Severity};

    fn make_host(host: &str) -> HostView {
        HostView::new(host, vec!["prod".to_string()])
    }

    fn req(uri: &str) -> axum::http::Request<axum::body::Body> {
        axum::http::Request::builder()
            .uri(uri)
            .body(axum::body::Body::empty())
            .unwrap()
    }

    fn sample_host() -> HostView {
        let mut hv = make_host("web");
        hv.containers.push(Container {
            id: "abc123".to_string(),
            name: "nginx".to_string(),
            image: "nginx:1.27".to_string(),
            image_digest: None,
            state: "running".to_string(),
            status: "Up 3 hours".to_string(),
            ports: Vec::new(),
            restart_policy: Some("unless-stopped".to_string()),
            health: Some("healthy".to_string()),
            compose_project: Some("edge".to_string()),
        });
        hv.audit = Some(AuditReport {
            host: "web".to_string(),
            findings: vec![
                Finding {
                    id: "EXP-001".to_string(),
                    title: "Port 8080 exposed to the internet".to_string(),
                    severity: Severity::Critical,
                    category: FindingCategory::Exposure,
                    detail: "0.0.0.0:8080 is reachable".to_string(),
                    recommendation: Some("Bind to the tailnet only".to_string()),
                },
                Finding {
                    id: "SSH-002".to_string(),
                    title: "Password authentication enabled".to_string(),
                    severity: Severity::Moderate,
                    category: FindingCategory::Ssh,
                    detail: "PasswordAuthentication yes".to_string(),
                    recommendation: None,
                },
            ],
        });
        hv
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let app = router(AppState::new(vec![sample_host()], false));
        let resp = app.oneshot(req("/healthz")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"ok");
    }

    #[tokio::test]
    async fn overview_renders_host_row() {
        let app = router(AppState::new(vec![sample_host()], false));
        let resp = app.oneshot(req("/")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("web"));
        assert!(html.contains("prod"));
        assert!(html.contains("Cerebro"));
        assert!(html.contains("do not expose"));
    }

    #[tokio::test]
    async fn overview_shows_read_only_badge() {
        let app = router(AppState::new(vec![sample_host()], true));
        let resp = app.oneshot(req("/")).await.unwrap();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.to_lowercase().contains("read-only"));
    }

    #[tokio::test]
    async fn host_detail_renders_for_known_host() {
        let app = router(AppState::new(vec![sample_host()], false));
        let resp = app.oneshot(req("/host/web")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("nginx"));
        assert!(html.contains("Port 8080 exposed to the internet"));
    }

    #[tokio::test]
    async fn host_detail_404_for_unknown_host() {
        let app = router(AppState::new(vec![sample_host()], false));
        let resp = app.oneshot(req("/host/missing")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"unknown host");
    }

    #[tokio::test]
    async fn audit_aggregates_findings_across_hosts() {
        let mut other = make_host("db");
        other.audit = Some(AuditReport {
            host: "db".to_string(),
            findings: vec![Finding {
                id: "ERR-009".to_string(),
                title: "Outstanding security errata".to_string(),
                severity: Severity::Important,
                category: FindingCategory::Errata,
                detail: "12 security updates pending".to_string(),
                recommendation: Some("Run cerebro update".to_string()),
            }],
        });
        let app = router(AppState::new(vec![sample_host(), other], false));
        let resp = app.oneshot(req("/audit")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Port 8080 exposed to the internet"));
        assert!(html.contains("Outstanding security errata"));
        assert!(html.contains("db"));

        let critical_pos = html.find("Port 8080 exposed to the internet").unwrap();
        let important_pos = html.find("Outstanding security errata").unwrap();
        assert!(critical_pos < important_pos);
    }

    #[tokio::test]
    async fn style_css_served_with_content_type() {
        let app = router(AppState::new(vec![sample_host()], false));
        let resp = app.oneshot(req("/assets/style.css")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ctype = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap();
        assert!(ctype.contains("text/css"));
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let css = String::from_utf8(body.to_vec()).unwrap();
        assert!(css.contains("--cerebro"));
    }

    #[tokio::test]
    async fn empty_fleet_overview_is_ok() {
        let app = router(AppState::new(Vec::new(), false));
        let resp = app.oneshot(req("/")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    async fn body_of(app: Router, uri: &str) -> String {
        let resp = app.oneshot(req(uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(body.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn dashboard_escapes_attacker_controlled_strings() {
        let mut hv = make_host("evil");
        hv.containers.push(Container {
            id: "x".to_string(),
            name: "<script>alert(1)</script>".to_string(),
            image: "img\"><img src=x onerror=alert(2)>".to_string(),
            image_digest: None,
            state: "running".to_string(),
            status: "Up".to_string(),
            ports: Vec::new(),
            restart_policy: None,
            health: None,
            compose_project: None,
        });
        let html = body_of(router(AppState::new(vec![hv], false)), "/host/evil").await;
        assert!(
            !html.contains("<script>alert(1)</script>"),
            "raw script tag leaked"
        );
        assert!(
            html.contains("&lt;script&gt;"),
            "expected HTML-escaped output"
        );
        assert!(!html.contains("onerror=alert(2)>"));
        assert!(
            !html.contains("template error"),
            "template failed to render"
        );
    }

    #[tokio::test]
    async fn https_auth_url_renders_as_a_link() {
        let mut hv = make_host("reauth");
        hv.auth_url = Some("https://login.tailscale.com/a/abc123".to_string());
        let html = body_of(router(AppState::new(vec![hv], false)), "/host/reauth").await;
        assert!(
            !html.contains("template error"),
            "auth_url branch failed to render"
        );
        // The anchor is rendered; the href value is HTML-escaped (minijinja encodes `/`
        // as &#x2f;), which browsers decode back to a working https link.
        assert!(html.contains("rel=\"noopener noreferrer\""));
        assert!(html.contains("login.tailscale.com"));
    }
}
