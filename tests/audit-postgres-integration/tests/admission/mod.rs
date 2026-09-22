use super::*;
pub(super) async fn run(
    store: &PgAudit,
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
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
        sqlx::raw_sql(restore).execute(admin).await?;
        // Dropped columns remain physical drift: the fresh schema contract intentionally rejects them.
        if !change.contains("ADD COLUMN") {
            PgAudit::new(pool.clone(), Integrity::Plain, control).await?;
        }
    }
    Ok(())
}
