//! Request task allocation figures exclude fixture startup and response inspection.
use super::*;
use std::{
    future::{Future, poll_fn},
    pin::pin,
};

/// Run in an isolated release process on the same fixture as the acceptance suite.
pub(crate) async fn measure(
    pg: &PgAudit,
    ledger: &PgAudit,
    pool: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let cancel = CancellationToken::new();
    for (index, profile) in ["small", "large", "mixed"].into_iter().enumerate() {
        let t = TenantId::parse(&format!("f47ac10b-58cc-4372-a567-0e02b2c3d6{index:02}"))?;
        let at = Timepoint::try_from(456_i64)?;
        let rows = sample_rows(t, profile, at)?;
        let bytes: usize = rows.iter().map(|r| r.canonical_bytes().len()).sum();
        for (mode, owner) in [("plain", pg), ("ledger", ledger)] {
            // Rollback keeps the identical batch fresh for each integrity mode.
            let start = Instant::now();
            let mut tx = pool.begin().await?;
            let checkout = start.elapsed();
            let held = Instant::now();
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                .bind(t.to_string())
                .execute(&mut *tx)
                .await?;
            let (added, alloc) = count_allocations(owner.append_batch_in_transaction(
                &mut tx,
                owner.try_admit(&rows)?,
                control,
            ))
            .await;
            added?;
            tx.rollback().await?;
            eprintln!(
                "WRITE {profile} {mode} rows=8 bytes={bytes} begin_us={} owner_hold_us={} allocs={} alloc_bytes={} poll_heap_peak={}",
                checkout.as_micros(),
                held.elapsed().as_micros(),
                alloc.count,
                alloc.bytes,
                alloc.peak
            );
        }
        let path = fixed_page(pg, &rows, t, at, control).await?;
        let app = router::<Session, _, _>(pg.clone(), Policy, TestClock);
        for required in [false, true] {
            for round in 0..6 {
                let audit = prepare(event(t, "query", &format!("attempt-{round}"), vec![])?, at)?;
                let req = request(
                    &path,
                    Some(Session {
                        audit: required.then(|| audit.clone()),
                        ..session(t)
                    }),
                    Some(budget(&cancel)?),
                )?;
                let start = Instant::now();
                let (response, alloc) = count_allocations(app.clone().oneshot(req)).await;
                let elapsed = start.elapsed();
                let (status, body, _) = inspect(response?).await?;
                assert_eq!(status, 200);
                assert!(body["nextCursor"].is_null());
                assert_eq!(body["entries"].as_array().map(Vec::len), Some(8));
                eprintln!(
                    "PAGE {profile} required={required} round={round} canonical={bytes} elapsed_us={} allocs={} alloc_bytes={} poll_heap_peak={}",
                    elapsed.as_micros(),
                    alloc.count,
                    alloc.bytes,
                    alloc.peak
                );
            }
        }
    }
    Ok(())
}
fn sample_rows(t: TenantId, profile: &str, at: Timepoint) -> anyhow::Result<Vec<PreparedAuditV1>> {
    let mut rows = Vec::new();
    for i in 0..8 {
        let id = format!("row-{i}");
        let overhead = prepare(event(t, "measure", &id, vec![])?, at)?
            .canonical_bytes()
            .len();
        let size = if profile == "large" || (profile == "mixed" && i % 2 == 1) {
            MAX_RECORD_BYTES - overhead
        } else {
            32
        };
        rows.push(prepare(event(t, "measure", &id, vec![7; size])?, at)?);
    }
    Ok(rows)
}
async fn fixed_page(
    pg: &PgAudit,
    rows: &[PreparedAuditV1],
    t: TenantId,
    at: Timepoint,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<String> {
    let anchor = prepare(event(t, "measure", "anchor", vec![])?, at)?;
    let after = committed(pg.append(&anchor, control).await)?
        .record()
        .position();
    let mut through = after;
    for row in rows {
        through = committed(pg.append(row, control).await)?
            .record()
            .position();
    }
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut coordinates = vec![2];
    coordinates.extend_from_slice(&t.octets());
    coordinates.extend_from_slice(&after.to_be_bytes());
    coordinates.extend_from_slice(&through.to_be_bytes());
    let path = format!(
        "/api/v2/audit/entries?limit=8&cursor={}",
        URL_SAFE_NO_PAD.encode(coordinates)
    );
    Ok(path)
}
#[derive(Default)]
struct Alloc {
    count: u64,
    bytes: u64,
    live: i64,
    peak: i64,
}
async fn count_allocations<F: Future>(future: F) -> (F::Output, Alloc) {
    let mut future = pin!(future);
    let mut total = Alloc::default();
    let result = poll_fn(|cx| {
        let mut result = std::task::Poll::Pending;
        let sample = allocation_counter::measure(|| result = future.as_mut().poll(cx));
        total.count += sample.count_total;
        total.bytes += sample.bytes_total;
        total.peak = total.peak.max(total.live + sample.bytes_max as i64);
        total.live += sample.bytes_current;
        result
    })
    .await;
    (result, total)
}
