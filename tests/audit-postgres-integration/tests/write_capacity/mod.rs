use super::*;
use futures::FutureExt;
use rss_audit_postgres::WriteBudget;

pub(super) async fn run(pool: &PgPool, control: &Control<'_, TestClock>) -> anyhow::Result<()> {
    let t = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d510")?;
    for (source, integrity) in [
        ("budget-plain", Integrity::Plain),
        ("budget-ledger", Integrity::Ledger(auth()?)),
    ] {
        let rows = (0..8)
            .map(|index| -> anyhow::Result<_> {
                Ok(prepare(
                    event(t, source, &format!("event-{index}"), vec![12; 128])?,
                    Timepoint::try_from(456_i64)?,
                )?)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let bytes = rows
            .iter()
            .map(|r| r.canonical_bytes().len())
            .sum::<usize>();
        let limit = u32::try_from(bytes)?;
        let capacity = WriteBudget::new(8, limit, limit)?;
        let pg = PgAudit::new(pool.clone(), integrity, capacity.clone(), control).await?;
        let all = capacity.reserve(8, bytes, control).await?;
        let attempt = pg
            .append(&rows[0], control)
            .now_or_never()
            .context("saturated writer waited")?;
        assert!(attempt.fold(
            |_| false,
            |e| matches!(e, Error::WriteBusy),
            |_| false,
            |_| false,
            |_| false,
            |_| false
        ));
        let cancel = CancellationToken::new();
        let deadline = Deadline::from_timeout(&TestClock, Duration::from_secs(3))?;
        let cancelled = Control::new(&TestClock, deadline, deadline, &cancel);
        let mut waiter = Box::pin(capacity.reserve(1, 1, &cancelled));
        assert!(waiter.as_mut().now_or_never().is_none());
        cancel.cancel();
        assert!(matches!(waiter.await, Err(Error::Cancelled(_))));
        let stop = Deadline::at(TestClock.now());
        assert!(matches!(
            capacity
                .reserve(1, 1, &Control::new(&TestClock, deadline, stop, &cancel))
                .await,
            Err(Error::Cancelled(_))
        ));
        let live = CancellationToken::new();
        assert!(matches!(
            capacity
                .reserve(1, 1, &Control::new(&TestClock, deadline, stop, &live))
                .await,
            Err(Error::Deadline(_))
        ));
        let mut next = Box::pin(capacity.reserve(8, bytes, control));
        assert!(next.as_mut().now_or_never().is_none());
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(t.to_string())
            .execute(&mut *tx)
            .await?;
        assert!(matches!(
            pg.append_in_transaction(&mut tx, &rows[0], control)
                .now_or_never(),
            Some(Err(Error::WriteBusy))
        ));
        assert!(
            pg.append_batch_in_transaction(&mut tx, pg.try_admit(&[])?, control)
                .await?
                .is_empty()
        );
        let foreign = WriteBudget::new(8, limit, limit)?;
        assert!(matches!(
            pg.append_batch_in_transaction(&mut tx, foreign.try_admit(&rows)?, control)
                .await,
            Err(Error::WriteLimit)
        ));
        let admitted = all.bind(&rows)?;
        let receipts = pg
            .append_batch_in_transaction(&mut tx, admitted, control)
            .await?;
        assert_eq!(receipts.len(), 8);
        assert!(receipts.iter().all(|receipt| receipt.inserted()));
        let granted = next.await?;
        drop(granted);
        tx.commit().await?;
        let mut too_many = rows.clone();
        too_many.push(rows[0].clone());
        assert!(matches!(pg.try_admit(&too_many), Err(Error::WriteLimit)));
        let mut bigger = rows.clone();
        bigger[0] = prepare(
            event(t, source, "event-0", vec![12; 129])?,
            Timepoint::try_from(456_i64)?,
        )?;
        assert!(matches!(pg.try_admit(&bigger), Err(Error::WriteLimit)));
        assert!(matches!(
            capacity.reserve(8, bytes - 1, control).await?.bind(&rows),
            Err(Error::WriteLimit)
        ));
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(t.to_string())
            .execute(&mut *tx)
            .await?;
        let changes = [
            prepare(
                event(t, source, "new-row", vec![])?,
                Timepoint::try_from(456_i64)?,
            )?,
            prepare(
                event(t, source, "event-7", vec![5])?,
                Timepoint::try_from(456_i64)?,
            )?,
        ];
        assert!(matches!(
            pg.append_batch_in_transaction(&mut tx, pg.try_admit(&changes)?, control)
                .await,
            Err(Error::Conflict)
        ));
        tx.rollback().await?;
        let page = committed(
            pg.read_page(Cursor::start(t), ReadLimit::new(100, 65536)?, control)
                .await,
        )?;
        assert!(
            !page
                .records()
                .iter()
                .any(|r| r.prepared().identity().event_id().as_str() == "new-row")
        );
    }
    Ok(())
}

/// Hold an admitted large batch in a real transaction while a small grant is polled.
/// The waiting path only has dimensions. It can construct the eight records after grant.
pub(super) async fn measure(pool: &PgPool, control: &Control<'_, TestClock>) -> anyhow::Result<()> {
    let t = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d699")?;
    let at = Timepoint::try_from(456_i64)?;
    let size = canonical_len(&event(t, "pressure", "large", vec![])?)?;
    let limit = u32::try_from(MAX_RECORD_BYTES)?;
    let capacity = WriteBudget::new(8, limit, limit)?;
    let store = PgAudit::new(pool.clone(), Integrity::Plain, capacity.clone(), control).await?;
    let granted = capacity.reserve(1, MAX_RECORD_BYTES, control).await?;
    let rows = [prepare(
        event(t, "pressure", "large", vec![0; MAX_RECORD_BYTES - size])?,
        at,
    )?];
    let admitted = granted.bind(&rows)?;
    let small_len = canonical_len(&event(t, "pressure", "small", vec![0; 32])?)? * 8;
    let mut pending = Box::pin(capacity.reserve(8, small_len, control));
    let start = Instant::now();
    assert!(pending.as_mut().now_or_never().is_none());
    let lease = Instant::now();
    let mut tx = pool.begin().await?;
    let begin = lease.elapsed();
    let hold = Instant::now();
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(t.to_string())
        .execute(&mut *tx)
        .await?;
    store
        .append_batch_in_transaction(&mut tx, admitted, control)
        .await?;
    let next = pending.await?;
    let waited = start.elapsed();
    tx.rollback().await?;
    let large_hold = hold.elapsed();
    let small = vec![prepare(event(t, "pressure", "small", vec![0; 32])?, at)?; 8];
    let batch = next.bind(&small)?;
    let second = Instant::now();
    let mut tx = pool.begin().await?;
    let second_begin = second.elapsed();
    let second_hold = Instant::now();
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(t.to_string())
        .execute(&mut *tx)
        .await?;
    store
        .append_batch_in_transaction(&mut tx, batch, control)
        .await?;
    tx.rollback().await?;
    eprintln!(
        "PRESSURE logical_peak={limit} small_bytes={small_len} queued=1 waiter_connections=0 wait_us={} large_begin_us={} large_hold_us={} small_begin_us={} small_hold_us={}",
        waited.as_micros(),
        begin.as_micros(),
        large_hold.as_micros(),
        second_begin.as_micros(),
        second_hold.elapsed().as_micros()
    );
    Ok(())
}
