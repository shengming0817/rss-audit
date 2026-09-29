#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
mod dto;
mod error;
mod policy;
mod query;
use axum::{
    Router,
    extract::{Request, State},
    response::Response,
    routing::get,
};
pub use error::QueryOutcome;
pub use policy::{
    AuditQueryPolicy, AuditRequestBudget, InvalidGrant, QueryGrant, QueryPolicyError, SelfAudit,
};
pub use query::{AuditQuery, InvalidQuery};
use rss_audit_postgres::{Control, PgAudit, ReadLimit};
use rss_contract::SafeErrorCode;
use rss_request_context::ExecutionTimer;
use std::sync::Arc;

struct App<P, T> {
    pg: PgAudit,
    policy: P,
    timer: T,
}
/// Mount the V2 tenant-query contract. Host middleware must authenticate each request and
/// insert `Arc<S>` and `AuditRequestBudget`. Credentials, auth challenges, listener/TLS and
/// session freshness are host-owned. No default authorization or implicit tenant exists.
///
/// ref: tokio-rs/axum axum/src/extension.rs@axum-v0.8.9 (request-scoped extensions).
///
/// ```compile_fail
/// use rss_audit_http_axum::router;
/// fn missing_policy(pg: rss_audit_postgres::PgAudit) { let _ = router(pg); }
/// ```
pub fn router<S, P, T>(pg: PgAudit, policy: P, timer: T) -> Router
where
    S: Send + Sync + 'static,
    P: AuditQueryPolicy<S>,
    T: ExecutionTimer + 'static,
{
    Router::new()
        .route(
            "/api/v2/audit/entries",
            get(list::<S, P, T>).head(|| async {
                error::no_store(axum::http::StatusCode::METHOD_NOT_ALLOWED.into_response())
            }),
        )
        .with_state(Arc::new(App { pg, policy, timer }))
}
use axum::response::IntoResponse;
async fn list<S, P, T>(State(app): State<Arc<App<P, T>>>, request: Request) -> Response
where
    S: Send + Sync + 'static,
    P: AuditQueryPolicy<S>,
    T: ExecutionTimer + 'static,
{
    error::no_store(execute::<S, P, T>(&app, request).await)
}
async fn execute<S, P, T>(app: &App<P, T>, request: Request) -> Response
where
    S: Send + Sync + 'static,
    P: AuditQueryPolicy<S>,
    T: ExecutionTimer + 'static,
{
    let Some(session) = request.extensions().get::<Arc<S>>() else {
        return error::safe(SafeErrorCode::Unauthenticated);
    };
    let Some(budget) = request.extensions().get::<AuditRequestBudget>() else {
        return error::safe(SafeErrorCode::Internal);
    };
    if budget.is_cancelled() || budget.deadline().is_expired(app.timer.now()) {
        return error::safe(SafeErrorCode::Unavailable);
    }
    let query = match AuditQuery::parse(request.uri().query()) {
        Ok(q) => q,
        Err(_) => return error::safe(SafeErrorCode::InvalidInput),
    };
    let grant = match app.policy.authorize(session, &query, budget) {
        Ok(grant) => grant,
        Err(reason) => {
            return error::safe(match reason {
                QueryPolicyError::Unauthenticated => SafeErrorCode::Unauthenticated,
                QueryPolicyError::Denied => SafeErrorCode::Forbidden,
                QueryPolicyError::Unavailable => SafeErrorCode::Unavailable,
            });
        }
    };
    let cursor = match query.cursor(grant.tenant) {
        Ok(c) => c,
        Err(_) => return error::safe(SafeErrorCode::InvalidInput),
    };
    let limit = match ReadLimit::new(
        query.limit(),
        u64::from(query.limit()) * rss_audit_core::MAX_RECORD_BYTES as u64,
    ) {
        Ok(limit) => limit,
        Err(_) => return error::safe(SafeErrorCode::Internal),
    };
    let control = Control::new(&app.timer, budget.deadline, budget.deadline, &budget.cancel);
    // Await the owner's result; dropping a timeout-wrapped transaction loses settlement.
    let attempt = match grant.audit {
        SelfAudit::NotRequired => {
            app.pg
                .read_tx_with_context(grant.tenant, &control, (), move |_, tx| {
                    Box::pin(async move {
                        let page = tx.read_page(cursor, limit).await?;
                        dto::PageDto::new(grant.tenant, &page)
                    })
                })
                .await
        }
        SelfAudit::Required(prepared) => {
            app.pg
                .write_tx_with_context(grant.tenant, &control, (), move |_, tx| {
                    Box::pin(async move {
                        let page = tx.read_page(cursor, limit).await?;
                        let response = dto::PageDto::new(grant.tenant, &page)?;
                        tx.append(&prepared).await?;
                        Ok::<_, rss_audit_postgres::Error>(response)
                    })
                })
                .await
        }
    };
    error::settle(attempt)
}
