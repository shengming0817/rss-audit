//! Isolated release fixture. The subscriber sees only operations inside the borrowed append.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
    instrument::WithSubscriber,
};
use tracing_subscriber::{
    Layer,
    layer::{Context, SubscriberExt},
};

#[derive(Default)]
struct Cost {
    ledger_sql: AtomicUsize,
    ledger_writes: AtomicUsize,
    sign: AtomicUsize,
    verify: AtomicUsize,
    audit_body: AtomicUsize,
    ledger_body: AtomicUsize,
}
struct Observer(Arc<Cost>);
#[derive(Default)]
struct Fields {
    ledger: bool,
    write: bool,
    bytes: usize,
}
impl Visit for Fields {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if matches!(field.name(), "summary" | "db.statement") {
            let sql = format!("{value:?}");
            self.ledger |= sql.contains("rss_ledger.");
            self.write |= sql.contains("rss_ledger.insert_entr");
        }
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "bytes" {
            self.bytes = value as usize;
        }
    }
}
impl<S: Subscriber> Layer<S> for Observer {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        let mut f = Fields::default();
        match event.metadata().target() {
            "sqlx::query" => {
                event.record(&mut f);
                self.0.ledger_sql.fetch_add(usize::from(f.ledger), Relaxed);
                self.0
                    .ledger_writes
                    .fetch_add(usize::from(f.write), Relaxed);
            }
            "batch_cost::verify" => {
                self.0.verify.fetch_add(1, Relaxed);
            }
            "batch_cost::sign" => {
                self.0.sign.fetch_add(1, Relaxed);
            }
            "batch_cost::audit_body" => {
                event.record(&mut f);
                self.0.audit_body.fetch_add(f.bytes, Relaxed);
            }
            "batch_cost::ledger_body" => {
                event.record(&mut f);
                self.0.ledger_body.fetch_add(f.bytes, Relaxed);
            }
            _ => {}
        }
    }
}
pub(super) async fn measure(
    plain: &PgAudit,
    ledger: &PgAudit,
    pool: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let at = Timepoint::try_from(321_i64)?;
    for (mode, owner, tenant) in [
        ("plain", plain, "3c54d1db-a1e9-42fc-b151-515263a11301"),
        ("ledger", ledger, "3c54d1db-a1e9-42fc-b151-515263a11302"),
    ] {
        let tenant = TenantId::parse(tenant)?;
        let seed = prepare(event(tenant, mode, "seed", vec![7])?, at)?;
        committed(owner.append(&seed, control).await)?;
        for profile in ["small", "large", "mixed"] {
            for n in [1_usize, 8, 32, 33, 64] {
                let mut rows = Vec::with_capacity(n);
                for i in 0..n {
                    let id = format!("r{i}");
                    let header = canonical_len(&event(tenant, mode, &id, vec![])?)?;
                    let bytes = if profile == "large" || (profile == "mixed" && i % 2 == 1) {
                        MAX_RECORD_BYTES - header
                    } else {
                        32
                    };
                    rows.push(prepare(event(tenant, mode, &id, vec![3; bytes])?, at)?);
                }
                let mut tx = pool.begin().await?;
                sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
                    .bind(tenant.to_string())
                    .execute(&mut *tx)
                    .await?;
                let cost = Arc::new(Cost::default());
                let subscriber = tracing_subscriber::registry().with(Observer(cost.clone()));
                let receipts = owner
                    .append_batch_in_transaction(&mut tx, owner.try_admit(&rows)?, control)
                    .with_subscriber(subscriber)
                    .await?;
                let recovered = receipts
                    .iter()
                    .zip(&rows)
                    .filter(|(r, input)| {
                        !std::ptr::eq(
                            r.record().prepared().canonical_bytes(),
                            input.canonical_bytes(),
                        )
                    })
                    .count();
                let receipt_copies = receipts
                    .iter()
                    .filter(|r| {
                        !std::ptr::eq(
                            r.record().clone().prepared().canonical_bytes(),
                            r.record().prepared().canonical_bytes(),
                        )
                    })
                    .count();
                assert!(receipts.iter().all(|r| r.inserted()));
                let sql = cost.ledger_sql.load(Relaxed);
                let writes = cost.ledger_writes.load(Relaxed);
                let verify = cost.verify.load(Relaxed);
                let sign = cost.sign.load(Relaxed);
                let audit_bytes = cost.audit_body.load(Relaxed);
                let ledger_bytes = cost.ledger_body.load(Relaxed);
                println!(
                    "BATCH {mode} {profile} n={n} audit_bytes={audit_bytes} recovered={recovered} receipt_copies={receipt_copies} ledger_sql={sql} writes={writes} verify={verify} sign={sign} ledger_bytes={ledger_bytes}"
                );
                assert_eq!((audit_bytes, recovered, receipt_copies), (0, 0, 0));
                if mode == "ledger" {
                    assert_eq!((verify, sign), (1, n));
                    assert_eq!(writes, n.div_ceil(32));
                    assert_eq!(sql, 2 + 2 * writes);
                    assert_eq!(ledger_bytes, seed.canonical_bytes().len());
                } else {
                    assert_eq!((sql, writes, verify, sign, ledger_bytes), (0, 0, 0, 0, 0));
                }
                tx.rollback().await?;
            }
        }
    }
    Ok(())
}
