use super::*;
use axum::{
    Router,
    body::{Body, to_bytes},
    http::Request,
    response::Response,
};
use rss_audit_http_axum::{
    AuditQuery, AuditQueryPolicy, AuditRequestBudget, QueryGrant, QueryOutcome, QueryPolicyError,
    SelfAudit, router,
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

struct Session {
    tenant: TenantId,
    rejection: Option<QueryPolicyError>,
    audit: Option<PreparedAuditV1>,
}
struct Policy;
impl AuditQueryPolicy<Session> for Policy {
    fn authorize(
        &self,
        s: &Session,
        _: &AuditQuery,
        _: &AuditRequestBudget,
    ) -> Result<QueryGrant, QueryPolicyError> {
        if let Some(error) = s.rejection {
            return Err(error);
        }
        QueryGrant::new(
            s.tenant,
            s.audit
                .clone()
                .map_or(SelfAudit::NotRequired, SelfAudit::Required),
        )
        .map_err(|_| QueryPolicyError::Unavailable)
    }
}
fn session(tenant: TenantId) -> Session {
    Session {
        tenant,
        rejection: None,
        audit: None,
    }
}
fn request(
    path: &str,
    session: Option<Session>,
    budget: Option<AuditRequestBudget>,
) -> anyhow::Result<Request<Body>> {
    let mut r = Request::builder()
        .uri(path)
        .header("authorization", "Bearer secret-client-token")
        .header("x-tenant-id", "forged-tenant")
        .body(Body::empty())?;
    if let Some(s) = session {
        r.extensions_mut().insert(Arc::new(s));
    }
    if let Some(b) = budget {
        r.extensions_mut().insert(b);
    }
    Ok(r)
}
fn budget(cancel: &CancellationToken) -> anyhow::Result<AuditRequestBudget> {
    Ok(AuditRequestBudget::new(
        Deadline::from_timeout(&TestClock, Duration::from_secs(10))?,
        cancel,
    ))
}
async fn inspect(mut response: Response) -> anyhow::Result<(u16, Value, Option<&'static str>)> {
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["content-type"], "application/json");
    let status = response.status().as_u16();
    let outcome = response
        .extensions_mut()
        .remove::<QueryOutcome>()
        .map(|o| {
            o.try_into_attempt().map(|a| {
                a.fold(
                    |_| "committed",
                    |_| "not-started",
                    |_| "rolled-back",
                    |_| "rollback-failed",
                    |_| "commit-unknown",
                    |_| "fenced",
                )
            })
        })
        .transpose()
        .map_err(|_| anyhow::anyhow!("shared outcome"))?;
    let bytes = to_bytes(response.into_body(), 1_000_000).await?;
    let raw = std::str::from_utf8(&bytes)?;
    for secret in [
        "secret-client-token",
        "payload-secret",
        "actor-private",
        "resource-private",
        "correlation-private",
        "request-private",
        "operation-private",
        "postgres://",
    ] {
        assert!(!raw.contains(secret));
    }
    Ok((status, serde_json::from_slice(&bytes)?, outcome))
}
pub(super) async fn run(
    pg: &PgAudit,
    ledger: &PgAudit,
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d491")?;
    let other = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d492")?;
    seed(pg, ledger, tenant, other, control).await?;
    let app = router::<Session, _, _>(pg.clone(), Policy, TestClock);
    let cancel = CancellationToken::new();
    boundary(&app, tenant, &cancel).await?;
    pages(pg, &app, tenant, other, &cancel, control).await?;
    routes(&app, tenant, &cancel).await?;
    self_audit_failures(pg, &app, tenant, &cancel, control).await?;
    corruption(&app, admin, tenant, &cancel).await?;
    interruptions(pg, admin, other, false).await?;
    interruptions(pg, admin, other, true).await?;
    unavailable(pool, other, &cancel, control).await?;
    Ok(())
}
async fn self_audit_failures(
    pg: &PgAudit,
    app: &Router,
    tenant: TenantId,
    cancel: &CancellationToken,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let existing = pg
        .prepare(event(tenant, "query", "conflict", vec![1])?, control)
        .await?;
    committed(pg.append(&existing, control).await)?;
    let changed = pg
        .prepare(event(tenant, "query", "conflict", vec![2])?, control)
        .await?;
    for fault in [
        None,
        Some(rss_audit_postgres::PgFault::RollbackFailedAfterAck),
    ] {
        if let Some(f) = fault {
            pg.inject_next_fault(f);
        }
        let (status, body, outcome) = inspect(
            app.clone()
                .oneshot(request(
                    "/api/v2/audit/entries",
                    Some(Session {
                        audit: Some(changed.clone()),
                        ..session(tenant)
                    }),
                    Some(budget(cancel)?),
                )?)
                .await?,
        )
        .await?;
        assert_eq!(status, if fault.is_none() { 500 } else { 503 });
        assert_eq!(
            outcome,
            Some(if fault.is_none() {
                "rolled-back"
            } else {
                "rollback-failed"
            })
        );
        assert!(body.get("entries").is_none());
    }
    unknown_commit(pg, app, tenant, cancel, control).await
}
async fn unknown_commit(
    pg: &PgAudit,
    app: &Router,
    tenant: TenantId,
    cancel: &CancellationToken,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let unknown = pg
        .prepare(event(tenant, "query", "unknown", vec![])?, control)
        .await?;
    pg.inject_next_fault(rss_audit_postgres::PgFault::CommitUnknownAfterAck);
    let (status, body, outcome) = inspect(
        app.clone()
            .oneshot(request(
                "/api/v2/audit/entries",
                Some(Session {
                    audit: Some(unknown.clone()),
                    ..session(tenant)
                }),
                Some(budget(cancel)?),
            )?)
            .await?,
    )
    .await?;
    assert_eq!((status, outcome), (503, Some("commit-unknown")));
    assert!(body.get("entries").is_none());
    assert!(!committed(pg.append(&unknown, control).await)?.inserted());
    let wrong = pg
        .prepare(event(super::tenant()?, "query", "wrong", vec![])?, control)
        .await?;
    assert!(QueryGrant::new(tenant, SelfAudit::Required(wrong)).is_err());
    Ok(())
}
async fn interruptions(
    pg: &PgAudit,
    admin: &PgPool,
    tenant: TenantId,
    abort: bool,
) -> anyhow::Result<()> {
    let mut blocker = admin.begin().await?;
    sqlx::query("LOCK TABLE rss_audit.records IN ACCESS EXCLUSIVE MODE")
        .execute(&mut *blocker)
        .await?;
    let cancel = CancellationToken::new();
    let app = router::<Session, _, _>(pg.clone(), Policy, TestClock);
    let request = request(
        "/api/v2/audit/entries",
        Some(session(tenant)),
        Some(budget(&cancel)?),
    )?;
    let task = tokio::spawn(app.oneshot(request));
    let pid = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let pid: Option<i32> = sqlx::query_scalar("SELECT pid FROM pg_stat_activity WHERE usename='audit_runtime' AND wait_event_type='Lock' ORDER BY query_start DESC LIMIT 1").fetch_optional(admin).await?;
            if let Some(pid) = pid { return Ok::<_, sqlx::Error>(pid); }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await??;
    if abort {
        task.abort();
        assert!(task.await.is_err());
    } else {
        cancel.cancel();
        let (status, _, outcome) = inspect(task.await??).await?;
        assert_eq!(status, 503);
        assert_eq!(outcome, Some("rollback-failed"));
    }
    blocker.rollback().await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let live: bool =
                sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1)")
                    .bind(pid)
                    .fetch_one(admin)
                    .await?;
            if !live {
                return Ok::<_, sqlx::Error>(());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;
    Ok(())
}

async fn seed(
    pg: &PgAudit,
    ledger: &PgAudit,
    tenant: TenantId,
    other: TenantId,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    for (t, id, owner) in [
        (tenant, "one", ledger),
        (tenant, "two", pg),
        (tenant, "three", pg),
        (other, "foreign", pg),
    ] {
        let p = owner.prepare(private_event(t, id)?, control).await?;
        committed(owner.append(&p, control).await)?;
    }
    Ok(())
}
fn private_event(tenant: TenantId, id: &str) -> anyhow::Result<AuditEventV1> {
    Ok(AuditEventV1::new(
        RecordIdentity::new(
            tenant,
            SourceIdentity::new(
                SourceId::parse("http")?,
                SourceContract::new(
                    ContractId::parse("fixture.operation")?,
                    ContractVersion::from_major(1)?,
                    SchemaDigest::parse(
                        "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                    )?,
                ),
            ),
            EventId::parse(id)?,
        ),
        EventFacts::new(
            ActorRef::new(ActorKind::parse("user")?, ActorId::parse("actor-private")?),
            Action::parse("updated")?,
            ResourceRef::new(
                ResourceKind::parse("device")?,
                ResourceId::parse("resource-private")?,
            ),
            Outcome::Succeeded,
            Timepoint::try_from(123_i64)?,
        ),
        EventContext::new(
            Coordinates::new(
                Some(rss_diag_context::CorrelationId::parse(
                    "correlation-private",
                )?),
                Some(rss_request_context::RequestId::parse("request-private")?),
                Some(OperationId::parse("operation-private")?),
            ),
            AuditPayload::new(b"payload-secret".to_vec())?,
        ),
    ))
}
async fn boundary(
    app: &Router,
    tenant: TenantId,
    cancel: &CancellationToken,
) -> anyhow::Result<()> {
    let b = budget(cancel)?;
    for (s, b, path, status, code) in [
        (
            None,
            Some(b.clone()),
            "/api/v2/audit/entries",
            401,
            "unauthenticated",
        ),
        (
            Some(session(tenant)),
            None,
            "/api/v2/audit/entries",
            500,
            "internal",
        ),
        (
            Some(Session {
                rejection: Some(QueryPolicyError::Denied),
                ..session(tenant)
            }),
            Some(b.clone()),
            "/api/v2/audit/entries",
            403,
            "forbidden",
        ),
        (
            Some(Session {
                rejection: Some(QueryPolicyError::Unauthenticated),
                ..session(tenant)
            }),
            Some(b.clone()),
            "/api/v2/audit/entries",
            401,
            "unauthenticated",
        ),
        (
            Some(Session {
                rejection: Some(QueryPolicyError::Unavailable),
                ..session(tenant)
            }),
            Some(b.clone()),
            "/api/v2/audit/entries",
            503,
            "unavailable",
        ),
        (
            Some(session(tenant)),
            Some(b.clone()),
            "/api/v2/audit/entries?tenantId=forged",
            400,
            "invalid-input",
        ),
    ] {
        let (actual, body, outcome) =
            inspect(app.clone().oneshot(request(path, s, b)?).await?).await?;
        assert_eq!(actual, status);
        assert_eq!(body["error"]["code"], code);
        assert_eq!(body.as_object().map(|v| v.len()), Some(1));
        assert!(outcome.is_none());
    }
    let stopped = CancellationToken::new();
    stopped.cancel();
    for b in [
        budget(&stopped)?,
        AuditRequestBudget::new(Deadline::at(TestClock.now()), cancel),
    ] {
        assert_eq!(
            inspect(
                app.clone()
                    .oneshot(request(
                        "/api/v2/audit/entries",
                        Some(session(tenant)),
                        Some(b)
                    )?)
                    .await?
            )
            .await?
            .0,
            503
        );
    }
    Ok(())
}
async fn pages(
    pg: &PgAudit,
    app: &Router,
    tenant: TenantId,
    other: TenantId,
    cancel: &CancellationToken,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let mut cursor = None::<String>;
    let mut first_cursor = None;
    for (position, id) in ["one", "two", "three"].into_iter().enumerate() {
        let body = audited_page(pg, app, tenant, position, cursor.as_deref(), control).await?;
        assert_entry(&body, tenant, position, id);
        cursor = body["nextCursor"].as_str().map(str::to_owned);
        if position == 0 {
            first_cursor = cursor.clone();
        }
    }
    assert!(cursor.is_none());
    let first_cursor = first_cursor.ok_or_else(|| anyhow::anyhow!("missing cursor"))?;
    assert_eq!(
        inspect(
            app.clone()
                .oneshot(request(
                    &format!("/api/v2/audit/entries?cursor={first_cursor}"),
                    Some(session(other)),
                    Some(budget(cancel)?)
                )?)
                .await?
        )
        .await?
        .0,
        400
    );
    Ok(())
}
async fn routes(app: &Router, tenant: TenantId, cancel: &CancellationToken) -> anyhow::Result<()> {
    for path in [
        "/api/v1/audit/entries",
        "/api/v2/audit/tenants/foreign/entries",
    ] {
        assert_eq!(
            app.clone()
                .oneshot(request(path, Some(session(tenant)), Some(budget(cancel)?))?)
                .await?
                .status(),
            404
        );
    }
    let mut head = request(
        "/api/v2/audit/entries",
        Some(session(tenant)),
        Some(budget(cancel)?),
    )?;
    *head.method_mut() = axum::http::Method::HEAD;
    assert_eq!(app.clone().oneshot(head).await?.status(), 405);
    Ok(())
}
async fn corruption(
    app: &Router,
    admin: &PgPool,
    tenant: TenantId,
    cancel: &CancellationToken,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE rss_audit.records SET recorded_at=0 WHERE tenant_id=$1::uuid AND position=0",
    )
    .bind(tenant.to_string())
    .execute(admin)
    .await?;
    let (status, body, outcome) = inspect(
        app.clone()
            .oneshot(request(
                "/api/v2/audit/entries",
                Some(session(tenant)),
                Some(budget(cancel)?),
            )?)
            .await?,
    )
    .await?;
    assert_eq!((status, outcome), (500, Some("rolled-back")));
    assert_eq!(body["error"]["code"], "internal");
    Ok(())
}
async fn unavailable(
    pool: &PgPool,
    other: TenantId,
    cancel: &CancellationToken,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let detached = PgPoolOptions::new()
        .max_connections(1)
        .connect_with((*pool.connect_options()).clone())
        .await?;
    let unavailable = PgAudit::new(detached.clone(), Integrity::Plain, control).await?;
    detached.close().await;
    let (status, _, outcome) = inspect(
        router::<Session, _, _>(unavailable, Policy, TestClock)
            .oneshot(request(
                "/api/v2/audit/entries",
                Some(session(other)),
                Some(budget(cancel)?),
            )?)
            .await?,
    )
    .await?;
    assert_eq!((status, outcome), (503, Some("not-started")));
    Ok(())
}

async fn audited_page(
    pg: &PgAudit,
    app: &Router,
    tenant: TenantId,
    position: usize,
    cursor: Option<&str>,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<Value> {
    let audit = pg
        .prepare(
            event(tenant, "query", &format!("q{position}"), vec![])?,
            control,
        )
        .await?;
    let path = cursor.map_or("/api/v2/audit/entries?limit=1".to_owned(), |c| {
        format!("/api/v2/audit/entries?limit=1&cursor={c}")
    });
    let (status, body, outcome) = inspect(
        app.clone()
            .oneshot(request(
                &path,
                Some(Session {
                    audit: Some(audit),
                    ..session(tenant)
                }),
                Some(budget(&CancellationToken::new())?),
            )?)
            .await?,
    )
    .await?;
    assert_eq!((status, outcome), (200, Some("committed")));
    Ok(body)
}
fn assert_entry(body: &Value, tenant: TenantId, position: usize, id: &str) {
    assert_eq!(body["tenantId"], tenant.to_string());
    assert_eq!(body["integrity"], "unverified");
    assert_eq!(body.as_object().map(|v| v.len()), Some(4));
    let entry = &body["entries"][0];
    assert_eq!(body["entries"].as_array().map(|v| v.len()), Some(1));
    assert_eq!(
        entry
            .as_object()
            .map(|v| v.keys().map(String::as_str).collect::<Vec<_>>()),
        Some(vec![
            "action",
            "eventId",
            "ledger",
            "occurredAt",
            "outcome",
            "position",
            "recordedAt",
            "sourceId"
        ])
    );
    assert_eq!(entry["eventId"], id);
    assert_eq!(entry["position"], position.to_string());
    assert_eq!(entry["occurredAt"], "123");
    if position == 0 {
        assert_eq!(
            entry["ledger"],
            json!({"chainId":"rss.audit.v1", "recordId":"v1:http:one", "sequence":"0"})
        );
    } else {
        assert!(entry["ledger"].is_null());
    }
}
