//! Independently mounted real TCP Axum host; authentication below is fixture-only.
use super::*;
use axum::{Router, middleware::{self, Next}, extract::Request, response::IntoResponse};
use rss_audit_http_axum::{AuditQuery, AuditQueryPolicy, AuditRequestBudget, QueryGrant, QueryPolicyError, SelfAudit};
use std::sync::Arc;
struct AuthenticatedFixtureSession(TenantId);
struct Policy;
impl AuditQueryPolicy<AuthenticatedFixtureSession> for Policy {
    fn authorize(&self, session: &AuthenticatedFixtureSession, _: &AuditQuery, _: &AuditRequestBudget) -> Result<QueryGrant, QueryPolicyError> {
        QueryGrant::new(session.0, SelfAudit::NotRequired).map_err(|_| QueryPolicyError::Unavailable)
    }
}
pub(super) async fn run(pg: PgAudit, tenant: TenantId) -> anyhow::Result<()> {
    let shutdown = CancellationToken::new();
    let host_cancel = shutdown.clone();
    let app = Router::new().route("/host-health", axum::routing::get(|| async { "host" }))
        .merge(rss_audit_http_axum::router::<AuthenticatedFixtureSession, _, _>(pg, Policy, HostClock))
        .layer(middleware::from_fn(move |mut req: Request, next: Next| {
            let cancel = host_cancel.clone();
            async move {
                // Fixture authentication only, not a deployable authentication implementation.
                if req.headers().get("authorization").is_some_and(|v| v == "Bearer fixture-only") {
                    req.extensions_mut().insert(Arc::new(AuthenticatedFixtureSession(tenant)));
                }
                let deadline = match Deadline::from_timeout(&HostClock, Duration::from_secs(10)) {
                    Ok(deadline) => deadline,
                    Err(_) => return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
                };
                req.extensions_mut().insert(AuditRequestBudget::new(deadline, &cancel));
                let mut response = next.run(req).await;
                if response.status() == axum::http::StatusCode::UNAUTHORIZED {
                    response.headers_mut().insert("www-authenticate", axum::http::HeaderValue::from_static("Bearer"));
                }
                response
            }
        }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let stopping = shutdown.clone();
    let server = tokio::spawn(async move { axum::serve(listener, app).with_graceful_shutdown(stopping.cancelled_owned()).await });
    let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).build()?;
    assert_eq!(client.get(format!("http://{address}/host-health")).send().await?.text().await?, "host");
    let url = format!("http://{address}/api/v2/audit/entries");
    let denied = client.get(&url).send().await?;
    assert_eq!(denied.status().as_u16(), 401);
    assert_eq!(denied.headers()["www-authenticate"], "Bearer");
    let response = client.get(&url).bearer_auth("fixture-only").header("x-tenant-id", "forged").send().await?;
    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body: serde_json::Value = response.json().await?;
    assert_eq!(body["tenantId"], tenant.to_string());
    assert_eq!(body["integrity"], "unverified");
    assert_eq!(body["entries"][0]["eventId"], "stable-event");
    assert!(body["entries"][0]["ledger"].is_null());
    assert_eq!(body["entries"][0].as_object().map(|v| v.len()), Some(8));
    assert!(body["nextCursor"].is_null());
    shutdown.cancel();
    server.await??;
    Ok(())
}
