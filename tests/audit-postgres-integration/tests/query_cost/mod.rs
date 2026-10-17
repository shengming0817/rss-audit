//! Observe executed SQL, not source symbols. Retain counts only, never query/parameter data.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{
    Event, Subscriber,
    field::{Field, Visit},
    instrument::WithSubscriber,
};
use tracing_subscriber::{
    Layer,
    layer::{Context, SubscriberExt},
};

#[derive(Clone, Default)]
struct Counts {
    queries: Arc<AtomicUsize>,
    catalog: Arc<AtomicUsize>,
}
#[derive(Default)]
struct Query {
    catalog: bool,
}
impl Visit for Query {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if matches!(field.name(), "db.statement" | "summary") {
            let sql = format!("{value:?}");
            self.catalog |= [
                "pg_proc",
                "pg_class",
                "pg_attribute",
                "pg_roles",
                "pg_namespace",
                "pg_constraint",
            ]
            .iter()
            .any(|table| sql.contains(table));
        }
    }
}
impl<S: Subscriber> Layer<S> for Counts {
    fn on_event(&self, event: &Event<'_>, _: Context<'_, S>) {
        if event.metadata().target() == "sqlx::query" {
            let mut query = Query::default();
            event.record(&mut query);
            self.queries.fetch_add(1, Ordering::Relaxed);
            if query.catalog {
                self.catalog.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

pub(super) async fn run(
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let cost_tenant = TenantId::parse("e09e9963-6bbc-48c4-9a25-0a1682e55762")?;
    for wide in [false, true] {
        if wide {
            sqlx::raw_sql("CREATE SCHEMA audit_cost_unrelated; DO $$ BEGIN FOR i IN 1..200 LOOP EXECUTE format('CREATE FUNCTION audit_cost_unrelated.f%s() RETURNS integer LANGUAGE sql AS %L', i, 'SELECT 1'); END LOOP; END $$")
                .execute(admin).await?;
        }
        for ledger in [false, true] {
            let counts = Counts::default();
            let subscriber = tracing_subscriber::registry().with(counts.clone());
            async {
                let store = PgAudit::new(
                    pool.clone(),
                    if ledger {
                        Integrity::Ledger(auth()?)
                    } else {
                        Integrity::Plain
                    },
                    control,
                )
                .await?;
                assert!(
                    counts.catalog.load(Ordering::Relaxed) > 0,
                    "observer must see startup validation"
                );
                counts.catalog.store(0, Ordering::Relaxed);
                counts.queries.store(0, Ordering::Relaxed);
                let e = event(
                    cost_tenant,
                    match (ledger, wide) {
                        (true, false) => "cost-ledger",
                        (false, false) => "cost-plain",
                        (true, true) => "cost-ledger-wide",
                        (false, true) => "cost-plain-wide",
                    },
                    "id",
                    vec![1],
                )?;
                let id = e.identity().clone();
                let staged = committed(
                    store
                        .write_tx_with_context(
                            cost_tenant,
                            control,
                            (id, Some(e)),
                            |(id, e), tx| {
                                Box::pin(async move {
                                    tx.append_with(id, |previous, now| {
                                        assert!(previous.is_none());
                                        Ok::<_, Error>(rss_audit_core::prepare(
                                            e.take().ok_or(Error::StorageContract)?,
                                            now,
                                        )?)
                                    })
                                    .await
                                })
                            },
                        )
                        .await,
                )?;
                assert!(staged.inserted());
                let replay = committed(store.append(staged.record().prepared(), control).await)?;
                assert!(!replay.inserted());
                let page = committed(
                    store
                        .read_page(
                            Cursor::start(cost_tenant),
                            ReadLimit::new(1024, 1048576)?,
                            control,
                        )
                        .await,
                )?;
                assert!(page.records().iter().any(|r| r.prepared().canonical_bytes()
                    == staged.record().prepared().canonical_bytes()));
                assert!(counts.queries.load(Ordering::Relaxed) > 0);
                assert_eq!(
                    counts.catalog.load(Ordering::Relaxed),
                    0,
                    "business operations must not inspect storage catalogs"
                );
                println!(
                    "audit query cost: ledger={ledger} wide={wide} queries={} catalog=0",
                    counts.queries.load(Ordering::Relaxed)
                );
                Ok::<_, anyhow::Error>(())
            }
            .with_subscriber(subscriber)
            .await?;
        }
    }
    Ok(())
}
