use super::*;
pub(super) async fn run(
    store: &PgAudit,
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    live_drift(store, admin, control).await?;
    sqlx::raw_sql("CREATE ROLE unrelated_audit_reader NOLOGIN; GRANT SELECT ON rss_audit.records TO unrelated_audit_reader").execute(admin).await?;
    // Grants to an unreachable role are permitted; no ACL grantee whitelist is implied.
    PgAudit::new(pool.clone(), Integrity::Plain, control).await?;
    assert!(
        PgAudit::new(admin.clone(), Integrity::Plain, control)
            .await
            .is_err()
    );
    for (change, restore) in [
        (
            "GRANT UPDATE ON rss_audit.records TO audit_runtime",
            "REVOKE UPDATE ON rss_audit.records FROM audit_runtime",
        ),
        (
            "GRANT SELECT ON rss_audit.records TO PUBLIC",
            "REVOKE SELECT ON rss_audit.records FROM PUBLIC",
        ),
        (
            "GRANT SELECT(canonical) ON rss_audit.records TO PUBLIC",
            "REVOKE SELECT(canonical) ON rss_audit.records FROM PUBLIC",
        ),
        (
            "GRANT USAGE ON SCHEMA rss_audit TO audit_runtime WITH GRANT OPTION",
            "REVOKE GRANT OPTION FOR USAGE ON SCHEMA rss_audit FROM audit_runtime",
        ),
        (
            "ALTER TABLE rss_audit.records NO FORCE ROW LEVEL SECURITY",
            "ALTER TABLE rss_audit.records FORCE ROW LEVEL SECURITY",
        ),
        (
            "ALTER POLICY tenant_scope ON rss_audit.records USING (true)",
            "ALTER POLICY tenant_scope ON rss_audit.records USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)",
        ),
        (
            "ALTER FUNCTION rss_audit.reserve(uuid) SET search_path=public",
            "ALTER FUNCTION rss_audit.reserve(uuid) SET search_path=pg_catalog,rss_audit",
        ),
        (
            "ALTER TABLE rss_audit.records ADD COLUMN extra integer DEFAULT 1",
            "ALTER TABLE rss_audit.records DROP COLUMN extra",
        ),
    ] {
        sqlx::raw_sql(change).execute(admin).await?;
        assert!(
            PgAudit::new(pool.clone(), Integrity::Plain, control)
                .await
                .is_err(),
            "accepted drift: {change}"
        );
        rolled_back(
            store
                .read_page(Cursor::start(tenant()?), ReadLimit::new(1, 10000)?, control)
                .await,
            |e| matches!(e, Error::Admission(_)),
        );
        rejects_callback(store, control).await?;
        sqlx::raw_sql(restore).execute(admin).await?;
        // Dropped columns remain physical drift: the fresh schema contract intentionally rejects them.
        if !change.contains("ADD COLUMN") {
            PgAudit::new(pool.clone(), Integrity::Plain, control).await?;
        }
    }
    Ok(())
}

async fn live_drift(
    store: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let prepared = store
        .prepare(
            event(tenant()?, "live-admission", "revoked", vec![])?,
            control,
        )
        .await?;
    for operation in 0..4 {
        let attempt = store
            .write_tx_with_context(
                tenant()?,
                control,
                (admin, &prepared),
                |(admin, prepared), tx| {
                    Box::pin(async move {
                        sqlx::raw_sql("GRANT UPDATE ON rss_audit.records TO audit_runtime")
                            .execute(*admin)
                            .await?;
                        // A successful pre-lock gate is never reused as authorization for a later public operation.
                        let tenant = tx.tenant_id();
                        let rejected = match operation {
                            0 => tx
                                .prepare(
                                    event(tenant, "live-admission", "prepare", vec![])
                                        .map_err(|_| Error::StorageContract)?,
                                )
                                .await
                                .map(|_| ()),
                            1 => tx
                                .find(
                                    decode_untrusted(prepared.canonical_bytes())?
                                        .event()
                                        .identity(),
                                )
                                .await
                                .map(|_| ()),
                            2 => tx
                                .read_page(Cursor::start(tenant), ReadLimit::new(1, 131072)?)
                                .await
                                .map(|_| ()),
                            _ => tx.append(prepared).await.map(|_| ()),
                        };
                        sqlx::raw_sql("REVOKE UPDATE ON rss_audit.records FROM audit_runtime")
                            .execute(*admin)
                            .await?;
                        rejected
                    })
                },
            )
            .await;
        rolled_back(attempt, |e| {
            matches!(e, TransactionError::Operation(Error::Admission(_)))
        });
    }
    Ok(())
}

async fn rejects_callback(store: &PgAudit, control: &Control<'_, TestClock>) -> anyhow::Result<()> {
    let entered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = entered.clone();
    rolled_back(
        store
            .write_tx_with_context(tenant()?, control, (), move |_, _| {
                Box::pin(async move {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok::<_, Error>(())
                })
            })
            .await,
        |e| matches!(e, TransactionError::Audit(Error::Admission(_))),
    );
    assert!(
        !entered.load(std::sync::atomic::Ordering::SeqCst),
        "callback entered after admission drift"
    );
    Ok(())
}
