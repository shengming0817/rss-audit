use crate::{AdmissionViolation as Violation, Error, MIGRATION_SQL};
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row};

pub(crate) async fn tenant(connection: &mut PgConnection, expected: TenantId) -> Result<(), Error> {
    admission(connection, Some(expected)).await
}
pub(crate) async fn validate(connection: &mut PgConnection) -> Result<(), Error> {
    admission(connection, None).await
}
async fn admission(connection: &mut PgConnection, tenant: Option<TenantId>) -> Result<(), Error> {
    let append = MIGRATION_SQL
        .split("$append$")
        .nth(1)
        .ok_or(Error::StorageContract)?;
    let reserve = MIGRATION_SQL
        .split("$reserve$")
        .nth(1)
        .ok_or(Error::StorageContract)?;
    let mut expected = vec![
        "heads:CHECK ((\"position\" >= 0))",
        "heads:PRIMARY KEY (tenant_id)",
        "records:CHECK (((octet_length(source_id) >= 1) AND (octet_length(source_id) <= 64)))",
        "records:CHECK (((octet_length(event_id) >= 1) AND (octet_length(event_id) <= 128)))",
        "records:CHECK ((\"position\" >= 0))",
        "records:CHECK ((recorded_at >= 0))",
        "records:CHECK (((octet_length(canonical) >= 1) AND (octet_length(canonical) <= 131072)))",
        "records:CHECK ((ledger_sequence >= 0))",
        "records:FOREIGN KEY (tenant_id) REFERENCES rss_audit.heads(tenant_id)",
        "records:PRIMARY KEY (tenant_id, source_id, event_id)",
        "records:UNIQUE (tenant_id, \"position\")",
        "records:UNIQUE (tenant_id, ledger_sequence)",
    ];
    expected.sort();
    let row = sqlx::query(include_str!("admission.sql"))
        .bind(append)
        .bind(reserve)
        .bind(expected)
        .bind(
            "(tenant_id = (NULLIF(current_setting('rss.tenant_id'::text, true), ''::text))::uuid)",
        )
        .fetch_one(connection)
        .await?;
    if let Some(expected) = tenant {
        let setting: Option<String> = row.try_get("tenant")?;
        if setting.as_deref().and_then(|s| TenantId::parse(s).ok()) != Some(expected) {
            return Err(Error::ScopeMismatch);
        }
    }
    for (column, category) in [
        ("roles", Violation::Role),
        ("schema", Violation::Schema),
        ("forced_rls", Violation::Rls),
        ("indexes", Violation::Shape),
        ("columns", Violation::Shape),
        ("constraints", Violation::Shape),
        ("policies", Violation::Rls),
        ("functions", Violation::Functions),
        ("privileges", Violation::Permissions),
    ] {
        if row.try_get::<Option<bool>, _>(column)? != Some(true) {
            return Err(Error::Admission(category));
        }
    }
    Ok(())
}
