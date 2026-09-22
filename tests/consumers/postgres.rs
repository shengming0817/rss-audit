//! Standalone public consumer, copied only into an isolated candidate workspace.
use rss_audit_core::*;
use rss_audit_postgres::{Committed, Control, Cursor, Error, Integrity, PgAudit, ReadLimit};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::{Clock, Deadline, ExecutionTimer, TenantId};
use rss_transactional_messaging::transaction::LocalTxAttempt;
use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions, PgSslMode},
};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

struct HostClock;
impl Clock for HostClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}
impl ExecutionTimer for HostClock {
    async fn sleep_until(&self, deadline: Deadline) {
        tokio::task::unconstrained(tokio::time::sleep_until(deadline.instant().into())).await;
    }
}
fn committed<R>(attempt: LocalTxAttempt<Committed<R>, Error>) -> anyhow::Result<R> {
    attempt.fold(
        |v| Ok(v.into_value()),
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
        |e| Err(e.into()),
    )
}
fn event(tenant: TenantId) -> anyhow::Result<AuditEventV1> {
    Ok(AuditEventV1::new(
        RecordIdentity::new(
            tenant,
            SourceIdentity::new(
                SourceId::parse("consumer")?,
                SourceContract::new(
                    ContractId::parse("consumer.changed")?,
                    ContractVersion::from_major(1)?,
                    SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64)))?,
                ),
            ),
            EventId::parse("stable-event")?,
        ),
        EventFacts::new(
            ActorRef::new(ActorKind::parse("user")?, ActorId::parse("actor")?),
            Action::parse("changed")?,
            ResourceRef::new(ResourceKind::parse("device")?, ResourceId::parse("device")?),
            Outcome::Succeeded,
            Timepoint::try_from(1_i64)?,
        ),
        EventContext::new(
            Coordinates::new(None, None, None),
            AuditPayload::new(vec![1, 2, 3])?,
        ),
    ))
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if std::env::args().nth(1).as_deref() == Some("--child") {
        tokio::time::timeout(Duration::from_secs(60), run()).await??;
        return Ok(());
    }
    let executable = std::env::current_exe()?
        .into_os_string()
        .into_string()
        .map_err(|_| anyhow::anyhow!("non-UTF8 fixture executable"))?;
    std::process::exit(
        testkit::launch(vec!["--".to_owned(), executable, "--child".to_owned()]).await?,
    );
}
async fn run() -> anyhow::Result<()> {
    let network = testkit::bridge_network("audit-consumer").await?;
    let fixture = testkit::postgres_tls(
        testkit::NetworkAttachment {
            network: network.name(),
            dns_name: "audit-consumer",
        },
        testkit::PgTlsServerIdentity::MatchingHost,
    )
    .await?;
    let p = fixture.params();
    let options = PgConnectOptions::new()
        .host(&p.host)
        .port(p.port)
        .database(&p.database)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(fixture.ca_pem().as_bytes().to_vec());
    let admin = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options.clone().username(&p.username).password(&p.password))
        .await?;
    install(&admin).await?;
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(options.username("audit_consumer").password("test-only"))
        .await?;
    let clock = HostClock;
    let cancel = CancellationToken::new();
    let control = Control::new(
        &clock,
        Deadline::from_timeout(&clock, Duration::from_secs(40))?,
        &cancel,
    );
    #[cfg(feature = "ledger")]
    let mode = Integrity::Ledger(std::sync::Arc::new(rss_ledger::Authenticator::new(
        rss_ledger::KeyId::parse("consumer-key")?,
        vec![7; 32],
    )?));
    #[cfg(not(feature = "ledger"))]
    let mode = Integrity::Plain;
    let store = PgAudit::new(pool.clone(), mode, &control).await?;
    let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
    let request = store.prepare(event(tenant)?, &control).await?;
    assert!(committed(store.append(&request, &control).await)?.inserted());
    assert!(
        !committed(
            store
                .append(
                    &PreparedAuditV1::from_canonical_bytes(request.canonical_bytes())?,
                    &control
                )
                .await
        )?
        .inserted()
    );
    let page = committed(
        store
            .read_page(
                Cursor::start(tenant),
                ReadLimit::new(1, request.canonical_bytes().len() as u64)?,
                &control,
            )
            .await,
    )?;
    assert_eq!(
        page.records()[0].prepared().canonical_bytes(),
        request.canonical_bytes()
    );
    #[cfg(feature = "ledger")]
    assert_eq!(
        committed(
            store
                .read_verified(
                    tenant,
                    rss_ledger::Sequence::new(0),
                    rss_ledger_postgres::ReadLimit::new(1, 10000)?,
                    &control
                )
                .await
        )?
        .records()
        .len(),
        1
    );
    #[cfg(feature = "messaging")]
    borrowed(&store, &request, &admin, &fixture).await?;
    pool.close().await;
    admin.close().await;
    drop(fixture);
    drop(network);
    Ok(())
}
async fn install(admin: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE ROLE audit_owner NOLOGIN NOSUPERUSER NOBYPASSRLS; CREATE ROLE audit_consumer LOGIN PASSWORD 'test-only' NOSUPERUSER NOBYPASSRLS; GRANT CREATE ON DATABASE rss_test TO audit_owner;").execute(admin).await?;
    let mut c = admin.acquire().await?;
    sqlx::raw_sql("SET ROLE audit_owner")
        .execute(&mut *c)
        .await?;
    sqlx::raw_sql(rss_audit_postgres::MIGRATION_SQL)
        .execute(&mut *c)
        .await?;
    #[cfg(feature = "ledger")]
    sqlx::raw_sql(rss_ledger_postgres::MIGRATION_SQL)
        .execute(&mut *c)
        .await?;
    sqlx::raw_sql("RESET ROLE; GRANT USAGE ON SCHEMA rss_audit TO audit_consumer; GRANT SELECT ON ALL TABLES IN SCHEMA rss_audit TO audit_consumer; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_audit TO audit_consumer;").execute(&mut *c).await?;
    #[cfg(feature="ledger")]
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_ledger TO audit_consumer; GRANT SELECT ON ALL TABLES IN SCHEMA rss_ledger TO audit_consumer; GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA rss_ledger TO audit_consumer;").execute(&mut *c).await?;
    Ok(())
}
#[cfg(feature = "messaging")]
async fn borrowed(
    store: &PgAudit,
    request: &PreparedAuditV1,
    admin: &PgPool,
    fixture: &testkit::PgTlsFixture,
) -> anyhow::Result<()> {
    use rss_transactional_messaging::{
        fence::{Epoch, ExecutionBinding, StorageIdentity},
        policy::OperationDeadline,
    };
    use rss_transactional_messaging_postgres::*;
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS")
        .execute(admin)
        .await?;
    sqlx::raw_sql(MIGRATION_SQL).execute(admin).await?;
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO audit_consumer; GRANT SELECT ON rss_transactional_messaging.policy,rss_transactional_messaging.outbox TO audit_consumer; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(jsonb),rss_transactional_messaging.append_outbox(bytea,jsonb),rss_transactional_messaging.check_execution() TO audit_consumer;").execute(admin).await?;
    let tenant = request.append_request().ledger().tenant();
    sqlx::query("INSERT INTO rss_transactional_messaging.storage_lineage VALUES(true,$1,$2)")
        .bind([1_u8; 16].as_slice())
        .bind([2_u8; 16].as_slice())
        .execute(admin)
        .await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,1)")
        .bind(tenant.to_string())
        .execute(admin)
        .await?;
    let p = fixture.params();
    let runtime = PgRuntime::connect_producer(
        PgConfig::new(
            &p.host,
            p.port,
            &p.database,
            "audit_consumer",
            PgPassword::new("test-only"),
            PgPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?,
        ),
        HostClock,
        ExecutionBinding::new(
            StorageIdentity::new([1; 16], [2; 16])?,
            vec![(tenant, Epoch::new(1)?)],
        )?,
    )
    .await?;
    let writing = request.clone();
    let audit = store.clone();
    let deadline = OperationDeadline::from_cutoff(
        Deadline::from_timeout(&HostClock, Duration::from_secs(10))?,
        &HostClock,
    );
    let replay = runtime
        .local_tx(tenant, deadline, move |tx| {
            Box::pin(async move { audit.append_in(tx, &writing).await.map_err(PgError::from) })
        })
        .await
        .fold(Ok, Err, Err, Err, Err, Err)?;
    assert!(!replay.inserted());
    runtime.close().await;
    Ok(())
}
