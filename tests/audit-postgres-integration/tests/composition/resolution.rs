use super::*;
use rss_audit_postgres::PgFault;

pub(super) async fn run(
    plain: &PgAudit,
    ledger: &PgAudit,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    for (source, store) in [("resolve-plain", plain), ("resolve-ledger", ledger)] {
        let e = event(tenant()?, source, "id", vec![1])?;
        let id = e.identity().clone();
        let prepared = committed(
            store
                .write_tx_with_context(tenant()?, control, (&id, Some(e)), |(id, e), tx| {
                    Box::pin(async move {
                        let staged = tx
                            .append_with(id, |previous, now| {
                                assert!(previous.is_none());
                                Ok::<_, Error>(rss_audit_core::prepare(
                                    e.take().ok_or(Error::StorageContract)?,
                                    now,
                                )?)
                            })
                            .await?;
                        assert!(staged.inserted());
                        Ok::<_, Error>(staged.record().prepared().clone())
                    })
                })
                .await,
        )?;
        // Cross a database timestamp second, then prove replay retains the stored bytes.
        tokio::time::sleep(Duration::from_secs(1)).await;
        committed(
            store
                .write_tx_with_context(
                    tenant()?,
                    control,
                    (&id, &prepared),
                    |(id, prepared), tx| {
                        Box::pin(async move {
                            let staged = tx
                                .append_with(id, |previous, now| {
                                    let previous = previous.ok_or(Error::StorageContract)?;
                                    assert!(
                                        now.unix_seconds()
                                            > decode_untrusted(prepared.canonical_bytes())?
                                                .recorded_at()
                                                .unix_seconds()
                                    );
                                    Ok::<_, Error>(previous.prepared().clone())
                                })
                                .await?;
                            assert!(!staged.inserted());
                            assert_eq!(
                                staged.record().prepared().canonical_bytes(),
                                prepared.canonical_bytes()
                            );
                            Ok::<_, Error>(())
                        })
                    },
                )
                .await,
        )?;
        for wrong_identity in [false, true] {
            let changed = event(
                tenant()?,
                source,
                if wrong_identity { "other" } else { "id" },
                vec![2],
            )?;
            rolled_back(
                store
                    .write_tx_with_context(
                        tenant()?,
                        control,
                        (&id, Some(changed)),
                        |(id, changed), tx| {
                            Box::pin(async move {
                                tx.append_with(id, |_, now| {
                                    Ok::<_, Error>(rss_audit_core::prepare(
                                        changed.take().ok_or(Error::StorageContract)?,
                                        now,
                                    )?)
                                })
                                .await
                            })
                        },
                    )
                    .await,
                |e| {
                    matches!(
                        e,
                        TransactionError::Operation(Error::Conflict | Error::ScopeMismatch)
                    )
                },
            );
        }
        store.inject_next_fault(PgFault::CommitUnknownAfterAck);
        let e = event(tenant()?, source, "unknown", vec![3])?;
        let id = e.identity().clone();
        let attempt = store
            .write_tx_with_context(tenant()?, control, (id.clone(), Some(e)), |(id, e), tx| {
                Box::pin(async move {
                    tx.append_with(id, |_, now| {
                        Ok::<_, Error>(rss_audit_core::prepare(
                            e.take().ok_or(Error::StorageContract)?,
                            now,
                        )?)
                    })
                    .await
                })
            })
            .await;
        assert!(attempt.fold(
            |_| false,
            |_| false,
            |_| false,
            |_| false,
            |_| true,
            |_| false
        ));
        committed(
            store
                .write_tx_with_context(tenant()?, control, id, |id, tx| {
                    Box::pin(async move {
                        let staged = tx
                            .append_with(id, |previous, _| {
                                Ok::<_, Error>(
                                    previous.ok_or(Error::StorageContract)?.prepared().clone(),
                                )
                            })
                            .await?;
                        assert!(!staged.inserted());
                        Ok::<_, Error>(())
                    })
                })
                .await,
        )?;
    }
    Ok(())
}

pub(super) async fn isolation(pool: &PgPool) -> anyhow::Result<()> {
    let isolated = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|c, _| {
            Box::pin(async move {
                sqlx::query("SET default_transaction_isolation='repeatable read'")
                    .execute(c)
                    .await?;
                Ok(())
            })
        })
        .connect_with(pool.connect_options().as_ref().clone())
        .await?;
    let clock = TestClock;
    let cancel = CancellationToken::new();
    let cutoff = Deadline::from_timeout(&clock, Duration::from_secs(5))?;
    let control = Control::new(&clock, cutoff, cutoff, &cancel);
    let store = PgAudit::new(isolated.clone(), Integrity::Plain, &control).await?;
    let e = event(tenant()?, "isolation", "id", vec![])?;
    let id = e.identity().clone();
    rolled_back(
        store
            .write_tx_with_context(tenant()?, &control, (id, Some(e)), |(id, e), tx| {
                Box::pin(async move {
                    tx.append_with(id, |_, now| {
                        Ok::<_, Error>(rss_audit_core::prepare(
                            e.take().ok_or(Error::StorageContract)?,
                            now,
                        )?)
                    })
                    .await
                })
            })
            .await,
        |e| matches!(e, TransactionError::Operation(Error::StorageContract)),
    );
    isolated.close().await;
    Ok(())
}
