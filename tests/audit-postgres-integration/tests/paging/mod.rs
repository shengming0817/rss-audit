use super::*;

pub(super) async fn run(
    pg: &PgAudit,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d490")?;
    let empty = committed(
        pg.read_page(Cursor::start(tenant), ReadLimit::new(1, 131072)?, control)
            .await,
    )?;
    assert!(empty.records().is_empty());
    assert!(empty.next().is_none());
    for id in ["one", "two", "three"] {
        let p = pg
            .prepare(event(tenant, "paging", id, vec![])?, control)
            .await?;
        committed(pg.append(&p, control).await)?;
    }
    let mut cursor = Some(Cursor::start(tenant));
    for position in 0..3 {
        let p = pg
            .prepare(
                event(tenant, "query", &format!("q{position}"), vec![])?,
                control,
            )
            .await?;
        let current = cursor.ok_or_else(|| anyhow::anyhow!("premature end"))?;
        let page = committed(
            pg.local_tx(tenant, control, move |tx| {
                Box::pin(async move {
                    let page = tx.read_page(current, ReadLimit::new(1, 131072)?).await?;
                    tx.append(&p).await?;
                    Ok::<_, Error>(page)
                })
            })
            .await,
        )?;
        assert_eq!(page.records()[0].position(), position);
        cursor = page.next();
    }
    assert!(
        cursor.is_none(),
        "query audit must not extend this enumeration"
    );
    invalid_and_missing(pg, admin, tenant, control).await
}

async fn invalid_and_missing(
    pg: &PgAudit,
    admin: &PgPool,
    tenant: TenantId,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let fresh = committed(
        pg.read_page(Cursor::start(tenant), ReadLimit::new(10, 131072)?, control)
            .await,
    )?;
    assert_eq!(fresh.records().len(), 6);
    rolled_back(
        pg.read_page(
            Cursor::resume(tenant, 0, 6)?,
            ReadLimit::new(1, 131072)?,
            control,
        )
        .await,
        |e| matches!(e, Error::InvalidBound),
    );
    let shortened = committed(
        pg.read_page(
            Cursor::resume(tenant, 0, 1)?,
            ReadLimit::new(10, 131072)?,
            control,
        )
        .await,
    )?;
    assert_eq!(shortened.records().len(), 1);
    assert!(shortened.next().is_none());
    let other = super::tenant()?;
    rolled_back(
        pg.local_tx(tenant, control, move |tx| {
            Box::pin(async move {
                tx.read_page(Cursor::start(other), ReadLimit::new(1, 131072)?)
                    .await
            })
        })
        .await,
        |e| matches!(e, TransactionError::Operation(Error::ScopeMismatch)),
    );
    sqlx::query("DELETE FROM rss_audit.records WHERE tenant_id=$1::uuid AND position=1")
        .bind(tenant.to_string())
        .execute(admin)
        .await?;
    rolled_back(
        pg.read_page(
            Cursor::resume(tenant, 0, 2)?,
            ReadLimit::new(2, 131072)?,
            control,
        )
        .await,
        |e| matches!(e, Error::StorageContract),
    );
    Ok(())
}
