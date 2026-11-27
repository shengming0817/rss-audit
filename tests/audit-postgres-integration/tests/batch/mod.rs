//! Logical order and durable outcomes across physical chunk boundaries.
use super::*;
use rss_audit_postgres::PgFault;

pub(super) async fn semantics(
    plain: &PgAudit,
    ledger: &PgAudit,
    pool: &PgPool,
    admin: &PgPool,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    for (mode, owner) in [("plain", plain), ("ledger", ledger)] {
        let tenant = TenantId::parse(if mode == "plain" {
            "10555663-d15a-46a0-bff3-9f73991fe730"
        } else {
            "10555663-d15a-46a0-bff3-9f73991fe731"
        })?;
        let at = Timepoint::try_from(456_i64)?;
        let make = |id: &str, payload| -> anyhow::Result<_> {
            Ok(prepare(event(tenant, mode, id, payload)?, at)?)
        };
        let old = make("old", vec![1])?;
        let original = committed(owner.append(&old, control).await)?;
        let mut rows = (0..33)
            .rev()
            .map(|i| make(&format!("r{i:02}"), vec![i]))
            .collect::<anyhow::Result<Vec<_>>>()?;
        rows.insert(1, old.clone());
        rows.extend([rows[0].clone(), old.clone()]);
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await?;
        let staged = owner
            .append_batch_in_transaction(&mut tx, owner.try_admit(&rows)?, control)
            .await?;
        for (i, (receipt, request)) in staged.iter().zip(&rows).enumerate() {
            assert_eq!(receipt.inserted(), i != 1 && i < 34);
            assert!(std::ptr::eq(
                receipt.record().prepared().canonical_bytes(),
                request.canonical_bytes()
            ));
        }
        assert_eq!(staged[1].record().position(), original.record().position());
        assert_eq!(
            staged[34].record().position(),
            staged[0].record().position()
        );
        assert_eq!(staged[35].record().position(), original.record().position());
        if mode == "ledger" {
            assert_eq!(staged[0].record().ledger_sequence(), Some(1));
            assert_eq!(staged[33].record().ledger_sequence(), Some(33));
        }
        tx.rollback().await?;

        let scratch = format!("batch-{mode}");
        sqlx::raw_sql("CREATE TABLE IF NOT EXISTS public.batch_effect(id text PRIMARY KEY); GRANT INSERT ON public.batch_effect TO audit_runtime").execute(admin).await?;
        let mut conflict = (0..32)
            .map(|i| make(&format!("rollback{i}"), vec![i]))
            .collect::<anyhow::Result<Vec<_>>>()?;
        conflict.push(make("old", vec![0])?);
        let attempt = owner
            .write_tx_with_context(
                tenant,
                control,
                (conflict, owner.clone(), scratch.clone()),
                |(rows, owner, id), tx| {
                    Box::pin(async move {
                        tx.with_connection_context(id, |id, c| {
                            Box::pin(async move {
                                sqlx::query("INSERT INTO public.batch_effect VALUES($1)")
                                    .bind(id.as_str())
                                    .execute(c)
                                    .await?;
                                Ok::<(), Error>(())
                            })
                        })
                        .await?;
                        tx.append_admitted(owner.try_admit(rows)?).await
                    })
                },
            )
            .await;
        rolled_back(attempt, |e| {
            matches!(e, TransactionError::Operation(Error::Conflict))
        });
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM public.batch_effect WHERE id=$1")
                .bind(scratch)
                .fetch_one(admin)
                .await?,
            0
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM rss_audit.records WHERE tenant_id=$1::uuid"
            )
            .bind(tenant.to_string())
            .fetch_one(admin)
            .await?,
            1
        );
        if mode == "ledger" {
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT seq FROM rss_ledger.heads WHERE tenant_id=$1::uuid"
                )
                .bind(tenant.to_string())
                .fetch_one(admin)
                .await?,
                0
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>(
                    "SELECT count(*) FROM rss_ledger.entries WHERE tenant_id=$1::uuid"
                )
                .bind(tenant.to_string())
                .fetch_one(admin)
                .await?,
                1
            );
        }

        owner.inject_next_fault(PgFault::CommitUnknownAfterAck);
        let outcome = owner
            .write_tx_with_context(
                tenant,
                control,
                (rows.clone(), owner.clone()),
                |(rows, owner), tx| {
                    Box::pin(async move { tx.append_admitted(owner.try_admit(rows)?).await })
                },
            )
            .await;
        assert!(outcome.fold(
            |_| false,
            |_| false,
            |_| false,
            |_| false,
            |_| true,
            |_| false
        ));
        let before = sqlx::query_as::<_,(String,i64,Option<i64>)>("SELECT event_id,position,ledger_sequence FROM rss_audit.records WHERE tenant_id=$1::uuid")
            .bind(tenant.to_string()).fetch_all(admin).await?;
        let coords: std::collections::HashMap<_, _> = before
            .into_iter()
            .map(|(id, pos, seq)| (id, (pos, seq)))
            .collect();
        let mut tx = pool.begin().await?;
        sqlx::query("SELECT set_config('rss.tenant_id',$1,true)")
            .bind(tenant.to_string())
            .execute(&mut *tx)
            .await?;
        let replay = owner
            .append_batch_in_transaction(&mut tx, owner.try_admit(&rows)?, control)
            .await?;
        for (receipt, request) in replay.iter().zip(&rows) {
            assert!(!receipt.inserted());
            let record = receipt.record();
            assert_eq!(record.prepared().recorded_at(), at);
            assert_eq!(
                record.prepared().canonical_bytes(),
                request.canonical_bytes()
            );
            assert_eq!(
                (
                    record.position() as i64,
                    record.ledger_sequence().map(|v| v as i64)
                ),
                coords[request.identity().event_id().as_str()]
            );
        }
        tx.commit().await?;
    }
    Ok(())
}
