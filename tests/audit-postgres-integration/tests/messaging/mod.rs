use super::*;
use rss_transactional_messaging::{
    fence::{Epoch, ExecutionBinding, StorageIdentity},
    inbox::{ConsumerGroup, IdempotencyDisposition, InboxStore},
    message::*,
    policy::{LeaseRenewalPolicy, OperationDeadline},
    transaction::*,
};
use rss_transactional_messaging_postgres::*;
mod local;

fn deadline() -> anyhow::Result<OperationDeadline> {
    Ok(OperationDeadline::from_cutoff(
        Deadline::from_timeout(&TestClock, Duration::from_secs(10))?,
        &TestClock,
    ))
}
struct Effect {
    integrity: Integrity,
    request: PreparedAuditV1,
    reject: bool,
}
impl PgConsumerEffect<Vec<u8>> for Effect {
    async fn apply(
        &self,
        tx: &mut PgTransaction<'_>,
        _: &MessageEnvelope<Vec<u8>>,
        _: OperationDeadline,
    ) -> Result<TerminalDisposition, PgConsumerEffectFailure> {
        rss_audit_postgres::lock_head_in(tx, &self.integrity)
            .await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        rss_audit_postgres::append_in(tx, &self.integrity, &self.request)
            .await
            .map_err(PgConsumerEffectFailure::infrastructure)?;
        let id = decode_untrusted(self.request.canonical_bytes())
            .map_err(PgConsumerEffectFailure::infrastructure)?
            .event()
            .identity()
            .event_id()
            .as_str()
            .to_owned();
        tx.with_connection(move |c| {
            Box::pin(async move {
                sqlx::query("INSERT INTO public.business_changes VALUES ($1)")
                    .bind(id)
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .await
        .map_err(PgConsumerEffectFailure::infrastructure)?;
        if self.reject {
            Err(PgConsumerEffectFailure::infrastructure(
                std::io::Error::other("fixture business rejection"),
            ))
        } else {
            Ok(TerminalDisposition::Succeeded)
        }
    }
}
struct Validator;
impl IngressValidator<Vec<u8>> for Validator {
    fn validate(
        &self,
        challenge: IngressChallenge<'_, Vec<u8>>,
    ) -> Result<VerifiedIngress, EnvelopeValidationFailure> {
        // Explicit fixture authority; production source authentication remains host-owned.
        Ok(challenge.verified())
    }
}
fn message(id: &str, payload: Vec<u8>) -> anyhow::Result<MessageEnvelope<Vec<u8>>> {
    Ok(MessageEnvelope::new(
        MessageId::parse(id)?,
        MessageMetadata::new(
            AuthoredMessageMetadata::new(
                tenant()?,
                Timepoint::try_from(1_i64)?,
                MessagingDomain::parse("audit-test")?,
                MessageRoute::parse("recorded")?,
                ContractIdentity::new(
                    ContractId::parse("audit-fixture.recorded")?,
                    ContractVersion::from_major(1)?,
                    SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64)))?,
                ),
            ),
            MessageMetadataExtensions::default(),
        ),
        payload,
    ))
}

#[allow(
    clippy::cognitive_complexity,
    reason = "Keep the borrowed transaction outcomes and their durable assertions together."
)]
pub(super) async fn run(
    plain: &PgAudit,
    ledger: &PgAudit,
    admin: &PgPool,
    fixture: &testkit::PgTlsFixture,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    install(admin).await?;
    let runtime = connect(fixture, "audit_runtime").await?;
    startup(plain, ledger, admin, fixture).await?;
    for (mode, integrity) in [
        ("borrowed-plain", Integrity::Plain),
        ("borrowed-ledger", Integrity::Ledger(auth()?)),
    ] {
        let prepared = plain
            .prepare(
                event(tenant()?, mode, "prepared-in-owner", vec![3])?,
                control,
            )
            .await?;
        let writer = integrity.clone();
        let request = prepared.clone();
        runtime
            .local_tx(tenant()?, deadline()?, move |tx| {
                Box::pin(async move {
                    rss_audit_postgres::validate_in(tx, &writer).await?;
                    rss_audit_postgres::lock_head_in(tx, &writer).await?;
                    let added = rss_audit_postgres::append_batch_in(
                        tx,
                        &writer,
                        &[request.clone(), request],
                    )
                    .await?;
                    assert!(added[0].inserted());
                    assert!(!added[1].inserted());
                    Ok(())
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
        let writer = integrity.clone();
        runtime
            .local_tx(tenant()?, deadline()?, move |tx| {
                Box::pin(async move {
                    assert!(
                        !rss_audit_postgres::append_in(tx, &writer, &prepared)
                            .await?
                            .inserted()
                    );
                    Ok(())
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
        let wrong = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d480")?;
        let foreign = plain
            .prepare(event(wrong, "scope", "foreign", vec![])?, control)
            .await?;
        runtime
            .local_tx(tenant()?, deadline()?, move |tx| {
                Box::pin(async move {
                    assert!(matches!(
                        rss_audit_postgres::append_in(tx, &integrity, &foreign).await,
                        Err(rss_audit_postgres::Error::ScopeMismatch)
                    ));
                    Ok(())
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
    }
    let inbox = PgInboxStore::new(
        runtime.clone(),
        LeaseRenewalPolicy::from_ttl(Duration::from_secs(30))?,
    )?;
    for (mode, store, integrity) in [
        ("plain", plain, Integrity::Plain),
        ("ledger", ledger, Integrity::Ledger(auth()?)),
    ] {
        for (case, reject, unknown) in [
            ("commit", false, false),
            ("rollback", true, false),
            ("unknown", false, true),
        ] {
            let id = format!("message-{mode}-{case}");
            scenario(
                store,
                admin,
                control,
                &runtime,
                &inbox,
                (&id, reject, unknown),
                integrity.clone(),
            )
            .await?;
        }
    }
    Box::pin(local::run(ledger, admin, fixture, control, &runtime)).await?;
    fenced(ledger, admin, &runtime, control).await?;
    runtime.close().await;
    Ok(())
}

async fn scenario(
    store: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
    runtime: &Arc<PgRuntime>,
    inbox: &PgInboxStore,
    case: (&str, bool, bool),
    integrity: Integrity,
) -> anyhow::Result<()> {
    let (id, reject, unknown) = case;
    let request = store
        .prepare(event(tenant()?, "message", id, vec![1])?, control)
        .await?;
    let envelope = message(id, request.canonical_bytes().to_vec())?;
    let metadata = envelope.metadata();
    let binding = verify_ingress(
        &Validator,
        ConsumerGroup::parse("audit-test")?,
        &SubscriptionIdentity::new(
            metadata.domain().clone(),
            metadata.route().clone(),
            metadata.contract().clone(),
        ),
        &envelope,
    )
    .map_err(|_| anyhow::anyhow!("fixture ingress rejected"))?;
    let IdempotencyDisposition::Acquired(claim) =
        inbox.claim(binding.identity(), deadline()?).await?
    else {
        anyhow::bail!("expected new claim")
    };
    if unknown {
        runtime.inject_next_transaction_fault(PgTransactionFault::CommitUnknownAfterAck);
    }
    let outcome = PgConsumerTx::receipt_only(
        runtime.clone(),
        Effect {
            integrity,
            request: request.clone(),
            reject,
        },
    )
    .execute(&claim, &envelope, binding.receipt_intent(), deadline()?)
    .await;
    assert_eq!(outcome.status(), expected_status(reject, unknown));
    assert_eq!(
        inbox
            .read_terminal(binding.identity(), deadline()?)
            .await?
            .is_some(),
        !reject
    );
    let actual: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.business_changes WHERE id=$1")
            .bind(id)
            .fetch_one(admin)
            .await?;
    assert_eq!(actual, i64::from(!reject));
    let retry = committed(store.append(&request, control).await)?;
    assert_eq!(retry.inserted(), reject);
    if unknown {
        assert!(matches!(
            inbox.claim(binding.identity(), deadline()?).await?,
            IdempotencyDisposition::Terminal(_)
        ));
    }
    Ok(())
}
fn expected_status(
    reject: bool,
    unknown: bool,
) -> rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus {
    use rss_transactional_messaging::observability::TransactionalMessagingTransactionStatus as Status;
    match (reject, unknown) {
        (_, true) => Status::CommitUnknown,
        (true, false) => Status::InfrastructureTransient,
        (false, false) => Status::Committed,
    }
}
async fn fenced(
    store: &PgAudit,
    admin: &PgPool,
    runtime: &Arc<PgRuntime>,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=2 WHERE tenant_id=$1::uuid",
    )
    .bind(tenant()?.to_string())
    .execute(admin)
    .await?;
    let request = store
        .prepare(event(tenant()?, "message", "fenced", vec![])?, control)
        .await?;
    let staged = request.clone();
    let integrity = Integrity::Ledger(auth()?);
    let outcome = runtime
        .local_tx(tenant()?, deadline()?, move |tx| {
            Box::pin(async move {
                rss_audit_postgres::append_in(tx, &integrity, &staged)
                    .await
                    .map_err(PgError::from)
            })
        })
        .await;
    assert!(outcome.fold(
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |_| false,
        |e| e.kind() == rss_transactional_messaging::error::MessagingErrorKind::OwnershipLost
    ));
    assert!(committed(store.append(&request, control).await)?.inserted());
    sqlx::query(
        "UPDATE rss_transactional_messaging.tenant_epoch SET epoch=1 WHERE tenant_id=$1::uuid",
    )
    .bind(tenant()?.to_string())
    .execute(admin)
    .await?;
    Ok(())
}
async fn install(admin: &PgPool) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE ROLE rss_tmsg_relay NOLOGIN NOBYPASSRLS;")
        .execute(admin)
        .await?;
    sqlx::raw_sql(MIGRATION_SQL).execute(admin).await?;
    sqlx::raw_sql("GRANT USAGE ON SCHEMA rss_transactional_messaging TO audit_runtime; GRANT SELECT ON rss_transactional_messaging.policy,rss_transactional_messaging.outbox TO audit_runtime; GRANT SELECT,INSERT,UPDATE,DELETE ON rss_transactional_messaging.inbox TO audit_runtime; GRANT EXECUTE ON FUNCTION rss_transactional_messaging.prepare_outbox_partitions(jsonb),rss_transactional_messaging.append_outbox(bytea,jsonb),rss_transactional_messaging.claim_outbox(uuid,text,integer,bigint),rss_transactional_messaging.next_outbox_wakeup(uuid,text),rss_transactional_messaging.outbox_lease(uuid,bigint,uuid,bigint,bigint,uuid),rss_transactional_messaging.settle_outbox(uuid,bigint,uuid,bigint,text,uuid),rss_transactional_messaging.check_execution() TO audit_runtime;").execute(admin).await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.storage_lineage VALUES(true,$1,$2)")
        .bind([1_u8; 16].as_slice())
        .bind([2_u8; 16].as_slice())
        .execute(admin)
        .await?;
    sqlx::query("INSERT INTO rss_transactional_messaging.tenant_epoch VALUES($1::uuid,1)")
        .bind(tenant()?.to_string())
        .execute(admin)
        .await?;
    Ok(())
}

async fn connect(fixture: &testkit::PgTlsFixture, role: &str) -> anyhow::Result<Arc<PgRuntime>> {
    let p = fixture.params();
    Ok(Arc::new(
        PgRuntime::connect(
            PgConfig::new(
                &p.host,
                p.port,
                &p.database,
                role,
                PgPassword::new("fixture-password"),
                PgPrivateCa::from_pem(fixture.ca_pem().as_bytes().to_vec())?,
            ),
            TestClock,
            ExecutionBinding::new(
                StorageIdentity::new([1; 16], [2; 16])?,
                vec![(tenant()?, Epoch::new(1)?)],
            )?,
        )
        .await?,
    ))
}

async fn startup(
    plain: &PgAudit,
    ledger: &PgAudit,
    admin: &PgPool,
    fixture: &testkit::PgTlsFixture,
) -> anyhow::Result<()> {
    sqlx::raw_sql("CREATE ROLE audit_borrower LOGIN PASSWORD 'fixture-password'; GRANT audit_runtime TO audit_borrower")
        .execute(admin).await?;
    let runtime = connect(fixture, "audit_borrower").await?;
    for (_store, grant, revoke, is_ledger) in [
        (
            plain,
            "GRANT UPDATE ON rss_audit.records TO audit_borrower",
            "REVOKE UPDATE ON rss_audit.records FROM audit_borrower",
            false,
        ),
        (
            ledger,
            "GRANT UPDATE ON rss_ledger.entries TO audit_borrower",
            "REVOKE UPDATE ON rss_ledger.entries FROM audit_borrower",
            true,
        ),
    ] {
        sqlx::raw_sql(grant).execute(admin).await?;
        let integrity = if is_ledger {
            Integrity::Ledger(auth()?)
        } else {
            Integrity::Plain
        };
        runtime
            .local_tx(tenant()?, deadline()?, move |tx| {
                Box::pin(async move {
                    let result = rss_audit_postgres::validate_in(tx, &integrity).await;
                    if is_ledger {
                        assert!(matches!(
                            result,
                            Err(rss_audit_postgres::Error::Ledger(
                                rss_ledger_postgres::Error::Admission(_)
                            ))
                        ));
                    } else {
                        assert!(matches!(
                            result,
                            Err(rss_audit_postgres::Error::Admission(_))
                        ));
                    }
                    Ok(())
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
        sqlx::raw_sql(revoke).execute(admin).await?;
        let integrity = if is_ledger {
            Integrity::Ledger(auth()?)
        } else {
            Integrity::Plain
        };
        runtime
            .local_tx(tenant()?, deadline()?, move |tx| {
                Box::pin(async move {
                    rss_audit_postgres::validate_in(tx, &integrity)
                        .await
                        .map_err(PgError::from)
                })
            })
            .await
            .fold(Ok, Err, Err, Err, Err, Err)?;
    }
    runtime.close().await;
    Ok(())
}
