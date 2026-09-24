use super::*;
mod locking;

pub(super) async fn run(
    plain: &PgAudit,
    ledger: &PgAudit,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    for (mode, store) in [("compose-plain", plain), ("compose-ledger", ledger)] {
        let e = event(tenant()?, mode, "final-fact", vec![7])?;
        let identity = e.identity().clone();
        let recovered_identity = identity.clone();
        let bytes = committed(
            store
                .local_tx(tenant()?, control, move |tx| {
                    Box::pin(async move {
                        tx.lock_head().await?;
                        tx.lock_head().await?;
                        assert!(tx.find(&identity).await?.is_none());
                        // Facts may now be derived from business SQL on the same connection.
                        let prepared = tx.prepare(e).await?;
                        assert!(tx.append(&prepared).await?.inserted());
                        let record = tx.find(&identity).await?.ok_or(Error::StorageContract)?;
                        assert_eq!(
                            record.prepared().canonical_bytes(),
                            prepared.canonical_bytes()
                        );
                        Ok::<_, Error>(prepared.canonical_bytes().to_vec())
                    })
                })
                .await,
        )?;
        let mut recovered = Vec::new();
        committed(
            store
                .local_tx_with_context(
                    tenant()?,
                    control,
                    (&recovered_identity, &bytes, &mut recovered),
                    |(identity, expected, recovered), tx| {
                        Box::pin(async move {
                            tx.lock_head().await?;
                            let r = tx.find(identity).await?.ok_or(Error::StorageContract)?;
                            assert_eq!(r.prepared().canonical_bytes(), expected.as_slice());
                            recovered.extend_from_slice(r.prepared().canonical_bytes());
                            assert!(!tx.append(r.prepared()).await?.inserted());
                            Ok::<_, Error>(())
                        })
                    },
                )
                .await,
        )?;
        assert_eq!(recovered, bytes);
    }
    Ok(())
}

pub(super) async fn single_connection(pool: &PgPool) -> anyhow::Result<()> {
    locking::run(pool).await?;
    let one = PgPoolOptions::new()
        .max_connections(1)
        .connect_with(pool.connect_options().as_ref().clone())
        .await?;
    let clock = TestClock;
    let cancel = CancellationToken::new();
    let control = Control::new(
        &clock,
        Deadline::from_timeout(&clock, Duration::from_secs(5))?,
        &cancel,
    );
    let store = PgAudit::new(one.clone(), Integrity::Ledger(auth()?), &control).await?;
    let e = event(tenant()?, "single-connection", "id", vec![4])?;
    committed(
        store
            .local_tx(tenant()?, &control, move |tx| {
                Box::pin(async move {
                    tx.lock_head().await?;
                    let p = tx.prepare(e).await?;
                    tx.append(&p).await?;
                    Ok::<_, Error>(())
                })
            })
            .await,
    )?;
    let wrong = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d480")?;
    let e = event(wrong, "scope", "id", vec![])?;
    rolled_back(
        store
            .local_tx(tenant()?, &control, move |tx| {
                Box::pin(async move {
                    tx.find(e.identity()).await?;
                    tx.prepare(e).await?;
                    Ok::<_, Error>(())
                })
            })
            .await,
        |e| matches!(e, TransactionError::Operation(Error::ScopeMismatch)),
    );
    one.close().await;
    Ok(())
}
