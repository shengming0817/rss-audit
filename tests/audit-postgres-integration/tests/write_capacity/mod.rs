use super::*;
use futures::FutureExt;
use rss_audit_postgres::WriteBudget;

pub(super) async fn run(
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let t = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d510")?;
    for (source, integrity) in [
        ("budget-plain", Integrity::Plain),
        ("budget-ledger", Integrity::Ledger(auth()?)),
    ] {
        let rows = eight_rows(t, source)?;
        let bytes = rows
            .iter()
            .map(|r| r.canonical_bytes().len())
            .sum::<usize>();
        let limit = u32::try_from(bytes)?;
        let capacity = WriteBudget::new(8, limit, limit)?;
        let pg = PgAudit::new(pool.clone(), integrity, capacity.clone(), control).await?;
        handoff(pool, &pg, &capacity, &rows, bytes, control).await?;
        batch_limits(&pg, &capacity, &rows, bytes, control).await?;
        late_conflict(pool, &pg, t, source, control).await?;
    }
    interrupted_stage(pool, admin, control).await?;
    corrupted_replay(pool, admin, control).await?;
    Ok(())
}

async fn handoff(
    pool: &PgPool,
    pg: &PgAudit,
    capacity: &WriteBudget,
    rows: &[PreparedAuditV1],
    bytes: usize,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let all = capacity.reserve(8, bytes, control).await?;
    busy_owner(pg, &rows[0], control)?;
    cancelled_waiter(capacity).await?;
    let mut next = Box::pin(capacity.reserve(8, bytes, control));
    assert!(next.as_mut().now_or_never().is_none());
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(rows[0].identity().tenant().to_string())
        .execute(&mut *tx)
        .await?;
    busy_borrowed(pg, &mut tx, rows, u32::try_from(bytes)?, control).await?;
    let admitted = all.bind(rows)?;
    let receipts = pg
        .append_batch_in_transaction(&mut tx, admitted, control)
        .await?;
    assert_eq!(receipts.len(), 8);
    assert!(receipts.iter().all(|receipt| receipt.inserted()));
    let granted = next.await?;
    drop(granted);
    tx.commit().await?;
    Ok(())
}

fn busy_owner(
    pg: &PgAudit,
    record: &PreparedAuditV1,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let attempt = pg
        .append(record, control)
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
    Ok(())
}

fn eight_rows(t: TenantId, source: &str) -> anyhow::Result<Vec<PreparedAuditV1>> {
    (0..8)
        .map(|index| -> anyhow::Result<_> {
            Ok(prepare(
                event(t, source, &format!("event-{index}"), vec![12; 128])?,
                Timepoint::try_from(456_i64)?,
            )?)
        })
        .collect()
}
async fn cancelled_waiter(capacity: &WriteBudget) -> anyhow::Result<()> {
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
    Ok(())
}
async fn busy_borrowed(
    pg: &PgAudit,
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    rows: &[PreparedAuditV1],
    limit: u32,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    assert!(matches!(
        pg.append_in_transaction(tx, &rows[0], control)
            .now_or_never(),
        Some(Err(Error::WriteBusy))
    ));
    assert!(
        pg.append_batch_in_transaction(tx, pg.try_admit(&[])?, control)
            .await?
            .is_empty()
    );
    let live = CancellationToken::new();
    let cutoff = Deadline::at(TestClock.now());
    let expired = Control::new(&TestClock, cutoff, cutoff, &live);
    assert!(matches!(
        pg.append_in_transaction(tx, &rows[0], &expired).await,
        Err(Error::Deadline(_))
    ));
    let foreign = WriteBudget::new(8, limit, limit)?;
    assert!(matches!(
        pg.append_batch_in_transaction(tx, foreign.try_admit(rows)?, control)
            .await,
        Err(Error::WriteLimit)
    ));
    assert!(matches!(
        pg.append_batch_in_transaction(tx, foreign.try_admit(rows)?, &expired)
            .await,
        Err(Error::Deadline(_))
    ));
    Ok(())
}
async fn batch_limits(
    pg: &PgAudit,
    capacity: &WriteBudget,
    rows: &[PreparedAuditV1],
    bytes: usize,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let id = rows[0].identity();
    let t = id.tenant();
    let source = id.source().source_id().as_str();
    let mut too_many = rows.to_vec();
    too_many.push(rows[0].clone());
    assert!(matches!(pg.try_admit(&too_many), Err(Error::WriteLimit)));
    let mut bigger = rows.to_vec();
    bigger[0] = prepare(
        event(t, source, "event-0", vec![12; 129])?,
        Timepoint::try_from(456_i64)?,
    )?;
    assert!(matches!(pg.try_admit(&bigger), Err(Error::WriteLimit)));
    assert!(matches!(
        capacity.reserve(8, bytes - 1, control).await?.bind(rows),
        Err(Error::WriteLimit)
    ));
    Ok(())
}
async fn late_conflict(
    pool: &PgPool,
    pg: &PgAudit,
    t: TenantId,
    source: &str,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
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
    use sqlx::Acquire;
    let lease = Instant::now();
    let mut conn = pool.acquire().await?;
    let begin = lease.elapsed();
    let hold = Instant::now();
    let mut tx = conn.begin().await?;
    let checked_out = || pool.size() as usize - pool.num_idle();
    let before = checked_out();
    let mut pending = Box::pin(capacity.reserve(8, small_len, control));
    let start = Instant::now();
    assert!(pending.as_mut().now_or_never().is_none());
    let with_waiter = checked_out();
    assert_eq!(before, with_waiter);
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
    drop(conn);
    let large_hold = hold.elapsed();
    let (second_begin, second_held) = stage_small(pool, &store, next, t, at, control).await?;
    eprintln!(
        "PRESSURE logical_peak={limit} small_bytes={small_len} queued=1 occupied_before={before} occupied_waiting={with_waiter} wait_us={} large_checkout_us={} large_hold_us={} small_checkout_us={} small_hold_us={}",
        waited.as_micros(),
        begin.as_micros(),
        large_hold.as_micros(),
        second_begin.as_micros(),
        second_held.as_micros()
    );
    Ok(())
}

async fn stage_small(
    pool: &PgPool,
    store: &PgAudit,
    next: rss_audit_postgres::WriteReservation,
    t: TenantId,
    at: Timepoint,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<(Duration, Duration)> {
    use sqlx::Acquire;
    let small = vec![prepare(event(t, "pressure", "small", vec![0; 32])?, at)?; 8];
    let batch = next.bind(&small)?;
    let second = Instant::now();
    let mut conn = pool.acquire().await?;
    let second_begin = second.elapsed();
    let second_hold = Instant::now();
    let mut tx = conn.begin().await?;
    sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
        .bind(t.to_string())
        .execute(&mut *tx)
        .await?;
    store
        .append_batch_in_transaction(&mut tx, batch, control)
        .await?;
    tx.rollback().await?;
    drop(conn);
    Ok((second_begin, second_hold.elapsed()))
}

async fn corrupted_replay(
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let t = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d515")?;
    let store = PgAudit::new(pool.clone(), Integrity::Plain, write_budget()?, control).await?;
    let at = Timepoint::try_from(456_i64)?;
    let short = prepare(event(t, "corrupt", "replay", vec![])?, at)?;
    let long = prepare(event(t, "corrupt", "replay", vec![7; 100_000])?, at)?;
    committed(store.append(&long, control).await)?;
    rolled_back(store.append(&short, control).await, |e| {
        matches!(e, Error::Conflict)
    });
    for bytes in [vec![1], [long.canonical_bytes(), &[1]].concat()] {
        sqlx::query("UPDATE rss_audit.records SET canonical=$1 WHERE tenant_id=$2::uuid")
            .bind(bytes)
            .bind(t.to_string())
            .execute(admin)
            .await?;
        rolled_back(store.append(&short, control).await, |e| {
            matches!(e, Error::StorageContract)
        });
    }
    Ok(())
}

// The fixture advances only the operation cutoff after observing an actual blocked
// PostgreSQL writer. The server timeout and owner settlement deadline remain ample.
struct StepClock {
    cutoff: Deadline,
    advance: CancellationToken,
}
impl Clock for StepClock {
    fn now(&self) -> Instant {
        if self.advance.is_cancelled() {
            self.cutoff.instant().max(Instant::now())
        } else {
            Instant::now()
        }
    }
}
impl ExecutionTimer for StepClock {
    async fn sleep_until(&self, deadline: Deadline) {
        if deadline.instant() == self.cutoff.instant() {
            tokio::select! { () = self.advance.cancelled() => {}, () = TestClock.sleep_until(deadline) => {} }
        } else {
            TestClock.sleep_until(deadline).await;
        }
    }
}
async fn interrupted_stage(
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let t = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d516")?;
    let record = prepare(
        event(t, "settle", "blocked", vec![])?,
        Timepoint::try_from(456_i64)?,
    )?;
    let bytes = u32::try_from(record.canonical_bytes().len())?;
    let budget = WriteBudget::new(1, bytes, bytes)?;
    let store = PgAudit::new(pool.clone(), Integrity::Plain, budget.clone(), control).await?;
    let mut blocker = admin.begin().await?;
    sqlx::query("LOCK TABLE rss_audit.records IN SHARE MODE")
        .execute(&mut *blocker)
        .await?;
    let blocker_pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await?;
    let cutoff = Deadline::from_timeout(&TestClock, Duration::from_secs(20))?;
    let total = Deadline::from_timeout(&TestClock, Duration::from_secs(60))?;
    let clock = StepClock {
        cutoff,
        advance: CancellationToken::new(),
    };
    let cancel = CancellationToken::new();
    let timed = Control::new(&clock, total, cutoff, &cancel);
    let dropped = CancellationToken::new();
    let marker = dropped.clone();
    let operation = store.write_tx_with_context(t, &timed, &record, move |row, tx| {
        Box::pin(async move {
            let _dropped = marker.drop_guard();
            tx.append(row).await?;
            Ok::<_, Error>(())
        })
    });
    let observe = async {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let waiting:bool=sqlx::query_scalar("SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid)))").bind(blocker_pid).fetch_one(admin).await?;
                if waiting {return Ok::<_,anyhow::Error>(());}
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await??;
        clock.advance.cancel();
        dropped.cancelled().await;
        assert!(matches!(
            budget.try_admit(std::slice::from_ref(&record)),
            Err(Error::WriteBusy)
        ));
        blocker.rollback().await?;
        Ok::<_, anyhow::Error>(())
    };
    let (result, observed) = tokio::join!(operation, observe);
    observed?;
    rolled_back(result, |e| {
        matches!(
            e,
            TransactionError::Audit(Error::Deadline(_))
                | TransactionError::Operation(Error::Deadline(_))
        )
    });
    budget.try_admit(std::slice::from_ref(&record))?;
    Ok(())
}
