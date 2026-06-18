//! Server-rendered local dashboard.
//!
//! A single-binary axum 0.7 application that renders the in-memory fleet cache as
//! plain HTML via minijinja. Everything is intentionally local-only: the templates
//! carry a persistent "do not expose" banner and an optional read-only badge so an
//! operator can never mistake this for a hardened, internet-facing control plane.

use std::sync::{Arc, OnceLock};

use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::Router;
use minijinja::{context, Environment};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::model::HostView;

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

/// One row of the overview table: the per-host summary the landing page renders.
#[derive(Serialize)]
struct HostSummary {
    name: String,
    groups: Vec<String>,
    health: crate::model::HostHealth,
    security_update_count: usize,
    max_severity: Option<crate::model::Severity>,
    container_count: usize,
    last_polled: Option<String>,
}

impl HostSummary {
    fn from_host(host: &HostView) -> Self {
        Self {
            name: host.name.clone(),
            groups: host.groups.clone(),
            health: host.health,
            security_update_count: host.security_update_count(),
            max_severity: host
                .audit
                .as_ref()
                .map(crate::model::AuditReport::max_severity),
            container_count: host.containers.len(),
            last_polled: host.last_polled.map(|ts| ts.to_rfc3339()),
        }
    }
}

/// A single finding annotated with the host it came from, for the aggregate page.
#[derive(Serialize)]
struct AuditRow {
    host: String,
    finding: crate::model::Finding,
}

fn environment() -> &'static Environment<'static> {
    static ENV: OnceLock<Environment<'static>> = OnceLock::new();
    ENV.get_or_init(|| {
        let mut env = Environment::new();
        // Templates are registered without a `.html` suffix, so force HTML escaping
        // explicitly: every `{{ ... }}` is attacker-influenced (container names, cron
        // commands, image tags) and must never be rendered as raw markup.
        env.set_auto_escape_callback(|_| minijinja::AutoEscape::Html);
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
    render(
        "overview",
        context! { hosts => hosts, read_only => state.read_only },
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
    render(
        "host",
        context! {
            host => host,
            security_update_count => host.security_update_count(),
            max_severity => host.audit.as_ref().map(crate::model::AuditReport::max_severity),
            read_only => state.read_only,
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
    render(
        "audit",
        context! { rows => rows, read_only => state.read_only },
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

/// Build the dashboard router with all routes wired to `state`.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(overview))
        .route("/host/:name", get(host_detail))
        .route("/audit", get(audit))
        .route("/healthz", get(healthz))
        .route("/assets/style.css", get(style))
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
