use super::*;

pub(super) async fn run(pool: &PgPool) -> anyhow::Result<()> {
    for ledger in [false, true] {
        race(pool, ledger).await?;
    }
    Ok(())
}

async fn race(pool: &PgPool, ledger: bool) -> anyhow::Result<()> {
    let clock = TestClock;
    let cancel = CancellationToken::new();
    let cutoff = Deadline::from_timeout(&clock, Duration::from_secs(10))?;
    let control = Control::new(&clock, cutoff, cutoff, &cancel);
    let store = PgAudit::new(
        pool.clone(),
        if ledger {
            Integrity::Ledger(auth()?)
        } else {
            Integrity::Plain
        },
        &control,
    )
    .await?;
    let e = event(
        tenant()?,
        if ledger { "race-ledger" } else { "race-plain" },
        "after-business",
        vec![1],
    )?;
    let identity = e.identity().clone();
    let (locked, wait_locked) = tokio::sync::oneshot::channel();
    let (release, released) = tokio::sync::oneshot::channel();
    let first = store.clone();
    let task = tokio::spawn(async move {
        let clock = TestClock;
        let cancel = CancellationToken::new();
        let cutoff = Deadline::from_timeout(&clock, Duration::from_secs(10))?;
        let control = Control::new(&clock, cutoff, cutoff, &cancel);
        committed(
            first
                .write_tx_with_context(tenant()?, &control, (), move |_, tx| {
                    Box::pin(async move {
                        locked.send(()).map_err(|_| Error::StorageContract)?;
                        released.await.map_err(|_| Error::StorageContract)?;
                        let prepared = tx.prepare(e).await?;
                        tx.append(&prepared).await?;
                        Ok::<_, Error>(())
                    })
                })
                .await,
        )
    });
    wait_locked.await?;
    let cutoff = Deadline::from_timeout(&clock, Duration::from_millis(500))?;
    let total = Deadline::from_timeout(&clock, Duration::from_secs(5))?;
    let short = Control::new(&clock, total, cutoff, &cancel);
    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let entered = started.clone();
    let attempt = store
        .write_tx_with_context(tenant()?, &short, (), move |_, _| {
            Box::pin(async move {
                entered.store(true, std::sync::atomic::Ordering::SeqCst);
                Ok::<_, Error>(())
            })
        })
        .await;
    assert!(
        !started.load(std::sync::atomic::Ordering::SeqCst),
        "write callback must not start before Audit and optional Ledger are locked"
    );
    attempt.fold(
        |_| Err(anyhow::anyhow!("unexpected commit")),
        |e| Err(anyhow::anyhow!("not started: {e:?}")),
        |e| {
            if operation_deadline(&e) {
                Ok(())
            } else {
                Err(anyhow::anyhow!("rolled back: {e:?}"))
            }
        },
        |e| Err(anyhow::anyhow!("rollback failed: {e:?}")),
        |e| Err(anyhow::anyhow!("commit unknown: {e:?}")),
        |e| Err(anyhow::anyhow!("fenced: {e:?}")),
    )?;
    // A reader of the same tenant must complete while the first writer holds both heads.
    let cutoff = Deadline::from_timeout(&clock, Duration::from_secs(1))?;
    let reader = Control::new(&clock, cutoff, cutoff, &cancel);
    committed(
        store
            .read_tx_with_context(tenant()?, &reader, (), |_, tx| {
                Box::pin(async move {
                    tx.read_page(
                        Cursor::start(tenant().map_err(|_| Error::StorageContract)?),
                        ReadLimit::new(1, 131072)?,
                    )
                    .await
                })
            })
            .await,
    )?;
    assert_head_locked(pool, false).await?;
    if ledger {
        assert_head_locked(pool, true).await?;
    }
    release
        .send(())
        .map_err(|_| anyhow::anyhow!("reservation owner ended early"))?;
    task.await??;
    committed(
        store
            .write_tx_with_context(tenant()?, &control, (), move |_, tx| {
                Box::pin(async move {
                    assert!(tx.find(&identity).await?.is_some());
                    Ok::<_, Error>(())
                })
            })
            .await,
    )?;
    Ok(())
}

async fn assert_head_locked(pool: &PgPool, ledger: bool) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "SELECT set_config('rss.tenant_id',$1,true),set_config('lock_timeout','100ms',true)",
    )
    .bind(tenant()?.to_string())
    .execute(&mut *tx)
    .await?;
    let result = if ledger {
        sqlx::query("SELECT rss_ledger.prepare_append($1::uuid,$2,'audit-fixture',1::smallint)")
            .bind(tenant()?.to_string())
            .bind(AUDIT_CHAIN_ID)
            .execute(&mut *tx)
            .await
    } else {
        sqlx::query("SELECT rss_audit.reserve($1::uuid)")
            .bind(tenant()?.to_string())
            .execute(&mut *tx)
            .await
    };
    let error = result
        .err()
        .ok_or_else(|| anyhow::anyhow!("head must already be locked"))?;
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("55P03")
    );
    tx.rollback().await?;
    Ok(())
}

fn operation_deadline(error: &TransactionError<Error>) -> bool {
    match error {
        TransactionError::Audit(error) | TransactionError::Operation(error) => {
            error.is_interrupted()
        }
        TransactionError::Rollback { operation, .. } => operation_deadline(operation),
    }
}
