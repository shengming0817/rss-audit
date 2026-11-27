use super::*;
use rss_transactional_messaging::transaction::LocalTxDeadlineStage as Stage;

struct InterruptPolicy(CancellationToken);
impl AuditQueryPolicy<Session> for InterruptPolicy {
    fn authorize(
        &self,
        session: &Session,
        query: &AuditQuery,
        budget: &AuditRequestBudget,
    ) -> Result<QueryGrant, QueryPolicyError> {
        let grant = Policy.authorize(session, query, budget)?;
        self.0.cancel();
        Ok(grant)
    }
}
struct PolicyClock {
    elapsed: CancellationToken,
    cutoff: Deadline,
}
impl Clock for PolicyClock {
    fn now(&self) -> Instant {
        if self.elapsed.is_cancelled() {
            self.cutoff.instant()
        } else {
            Instant::now()
        }
    }
}
impl ExecutionTimer for PolicyClock {
    async fn sleep_until(&self, deadline: Deadline) {
        TestClock.sleep_until(deadline).await
    }
}
pub(super) async fn run(
    pool: &PgPool,
    t: TenantId,
    control: &Control<'_, TestClock>,
) -> anyhow::Result<()> {
    let record = prepare(
        event(t, "policy", "interrupted", vec![1])?,
        Timepoint::try_from(456_i64)?,
    )?;
    let bytes = u32::try_from(record.canonical_bytes().len())?;
    for max in [1, bytes] {
        let domain = rss_audit_postgres::WriteBudget::new(1, max, max)?;
        let pg = PgAudit::new(pool.clone(), Integrity::Plain, domain.clone(), control).await?;
        let _occupied = domain.reserve(1, max as usize, control).await?;
        for cancel in [true, false] {
            check(pg.clone(), &record, t, cancel).await?;
        }
    }
    Ok(())
}
async fn check(
    pg: PgAudit,
    record: &PreparedAuditV1,
    t: TenantId,
    cancel: bool,
) -> anyhow::Result<()> {
    let token = CancellationToken::new();
    let elapsed = CancellationToken::new();
    let cutoff = Deadline::from_timeout(&TestClock, Duration::from_secs(3))?;
    let policy = InterruptPolicy(if cancel {
        token.clone()
    } else {
        elapsed.clone()
    });
    let app = router::<Session, _, _>(pg, policy, PolicyClock { elapsed, cutoff });
    let req = request(
        "/api/v2/audit/entries?limit=1",
        Some(Session {
            audit: Some(record.clone()),
            ..session(t)
        }),
        Some(AuditRequestBudget::new(cutoff, &token)),
    )?;
    let mut response = app.oneshot(req).await?;
    assert_eq!(response.status().as_u16(), 503);
    let attempt = response
        .extensions_mut()
        .remove::<QueryOutcome>()
        .context("classified interruption")?
        .try_into_attempt()
        .map_err(|_| anyhow::anyhow!("shared outcome"))?;
    assert!(attempt.fold(
        |_| false,
        |e| matches!(
            (cancel, e),
            (
                true,
                TransactionError::Audit(Error::Cancelled(Stage::Acquire))
            ) | (
                false,
                TransactionError::Audit(Error::Deadline(Stage::Acquire))
            )
        ),
        |_| false,
        |_| false,
        |_| false,
        |_| false
    ));
    Ok(())
}
