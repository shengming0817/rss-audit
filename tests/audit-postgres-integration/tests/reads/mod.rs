use super::*;
use rss_ledger::Sequence;

pub(super) async fn run(
    plain: &PgAudit,
    ledger: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let other = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d480")?;
    let one = plain
        .prepare(event(other, "read", "large", vec![5; 65536])?, control)
        .await?;
    committed(plain.append(&one, control).await)?;
    let bytes = one.canonical_bytes().len() as u64;
    assert_eq!(
        committed(
            plain
                .read_page(Cursor::start(other), ReadLimit::new(1, bytes)?, control)
                .await
        )?
        .records()
        .len(),
        1
    );
    rolled_back(
        plain
            .read_page(Cursor::start(other), ReadLimit::new(1, bytes - 1)?, control)
            .await,
        |e| matches!(e, Error::ReadBudgetExceeded),
    );
    let copy = one.clone();
    rolled_back(
        plain
            .local_tx(tenant()?, control, move |tx| {
                Box::pin(async move { tx.append(&copy).await })
            })
            .await,
        |e| matches!(e, Error::ScopeMismatch),
    );
    let count = committed(
        plain
            .local_tx(tenant()?, control, move |tx| {
                Box::pin(async move {
                    tx.with_connection(move |c| {
                        Box::pin(async move {
                            Ok(sqlx::query_scalar::<_, i64>(
                                "SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid",
                            )
                            .bind(other.to_string())
                            .fetch_one(c)
                            .await?)
                        })
                    })
                    .await
                })
            })
            .await,
    )?;
    assert_eq!(count, 0);
    let verified = committed(
        ledger
            .read_verified(
                tenant()?,
                Sequence::new(0),
                rss_ledger_postgres::ReadLimit::new(1024, 1_000_000)?,
                control,
            )
            .await,
    )?;
    assert!(verified.records().len() >= 5);
    rolled_back(
        plain
            .read_verified(
                tenant()?,
                Sequence::new(0),
                rss_ledger_postgres::ReadLimit::new(1, 10000)?,
                control,
            )
            .await,
        |e| matches!(e, Error::IntegrityRequired),
    );
    rolled_back(
        ledger
            .read_verified(
                tenant()?,
                Sequence::new(1),
                rss_ledger_postgres::ReadLimit::new(1, 1)?,
                control,
            )
            .await,
        |e| {
            matches!(
                e,
                Error::Ledger(rss_ledger_postgres::Error::ReadBudgetExceeded)
            )
        },
    );
    corruption(plain, ledger, admin, control, &one).await
}

async fn corruption(
    plain: &PgAudit,
    ledger: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
    one: &PreparedAuditV1,
) -> anyhow::Result<()> {
    ledger_metadata(ledger, admin, control).await?;
    let other = one.append_request().ledger().tenant();
    sqlx::query("UPDATE rss_audit.records SET recorded_at=0 WHERE tenant_id=$1::uuid")
        .bind(other.to_string())
        .execute(admin)
        .await?;
    rolled_back(
        plain
            .read_page(Cursor::start(other), ReadLimit::new(1, 100000)?, control)
            .await,
        |e| matches!(e, Error::StorageContract),
    );
    sqlx::query("UPDATE rss_audit.records SET recorded_at=$1 WHERE tenant_id=$2::uuid")
        .bind(
            decode_untrusted(one.canonical_bytes())?
                .recorded_at()
                .unix_seconds(),
        )
        .bind(other.to_string())
        .execute(admin)
        .await?;
    let original: Vec<u8> = sqlx::query_scalar(
        "SELECT payload FROM rss_ledger.entries WHERE tenant_id=$1::uuid AND seq=0",
    )
    .bind(tenant()?.to_string())
    .fetch_one(admin)
    .await?;
    sqlx::query("UPDATE rss_ledger.entries SET payload=decode('010203','hex') WHERE tenant_id=$1::uuid AND seq=0").bind(tenant()?.to_string()).execute(admin).await?;
    rolled_back(
        ledger
            .read_verified(
                tenant()?,
                Sequence::new(0),
                rss_ledger_postgres::ReadLimit::new(1, 10000)?,
                control,
            )
            .await,
        |e| matches!(e, Error::Ledger(_)),
    );
    sqlx::query("UPDATE rss_ledger.entries SET payload=$1 WHERE tenant_id=$2::uuid AND seq=0")
        .bind(original)
        .bind(tenant()?.to_string())
        .execute(admin)
        .await?;
    sqlx::query("DELETE FROM rss_audit.records WHERE tenant_id=$1::uuid")
        .bind(other.to_string())
        .execute(admin)
        .await?;
    rolled_back(
        plain
            .read_page(Cursor::start(other), ReadLimit::new(1, 100000)?, control)
            .await,
        |e| matches!(e, Error::StorageContract),
    );
    Ok(())
}

async fn ledger_metadata(
    ledger: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let original: Vec<u8> = sqlx::query_scalar(
        "SELECT canonical FROM rss_audit.records WHERE tenant_id=$1::uuid AND ledger_sequence=0",
    )
    .bind(tenant()?.to_string())
    .fetch_one(admin)
    .await?;
    let decoded = decode_untrusted(&original)?;
    let identity = decoded.event().identity();
    for update in [
        "UPDATE rss_audit.records SET source_id='corrupted' WHERE tenant_id=$1::uuid AND ledger_sequence=0",
        "UPDATE rss_audit.records SET event_id='corrupted' WHERE tenant_id=$1::uuid AND ledger_sequence=0",
        "UPDATE rss_audit.records SET recorded_at=0 WHERE tenant_id=$1::uuid AND ledger_sequence=0",
    ] {
        sqlx::query(update)
            .bind(tenant()?.to_string())
            .execute(admin)
            .await?;
        rolled_back(
            ledger
                .read_verified(
                    tenant()?,
                    Sequence::new(0),
                    rss_ledger_postgres::ReadLimit::new(1, 10000)?,
                    control,
                )
                .await,
            |e| matches!(e, Error::StorageContract),
        );
        sqlx::query("UPDATE rss_audit.records SET source_id=$2,event_id=$3,recorded_at=$4 WHERE tenant_id=$1::uuid AND ledger_sequence=0")
            .bind(tenant()?.to_string())
            .bind(identity.source().source_id().as_str())
            .bind(identity.event_id().as_str())
            .bind(decoded.recorded_at().unix_seconds())
            .execute(admin)
            .await?;
    }
    Ok(())
}
