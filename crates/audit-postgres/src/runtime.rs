use crate::{
    AuditTransaction, Control, Cursor, Error, Page, ReadLimit, StagedAppend, TransactionError,
    probe,
};
use futures::future::BoxFuture;
use rss_audit_core::{AuditEventV1, PreparedAuditV1};
use rss_contract::Timepoint;
use rss_request_context::{ExecutionTimer, TenantId};
use rss_transactional_messaging::transaction::{LocalTxAttempt, LocalTxDeadlineStage as Stage};
use sqlx::{Acquire, PgPool, Postgres, pool::PoolConnection};

/// Explicit integrity mode. There is no fallback from ledger failure to plain persistence.
#[derive(Clone)]
pub enum Integrity {
    /// Atomic append-only persistence without cryptographic integrity claims.
    Plain,
    /// Append the Audit bytes and ledger entry in the very same transaction.
    #[cfg(feature = "ledger")]
    Ledger(std::sync::Arc<rss_ledger::Authenticator>),
}
impl Integrity {
    pub(crate) const fn is_ledger(&self) -> bool {
        match self {
            Self::Plain => false,
            #[cfg(feature = "ledger")]
            Self::Ledger(_) => true,
        }
    }
}

/// Operation value after this owner's acknowledged COMMIT. Construction is private.
///
/// ```compile_fail
/// let forged = rss_audit_postgres::Committed(());
/// ```
#[derive(Debug)]
pub struct Committed<R>(R);
impl<R> Committed<R> {
    /// Inspect the acknowledged operation value.
    pub const fn value(&self) -> &R {
        &self.0
    }
    /// Consume the commit receipt.
    pub fn into_value(self) -> R {
        self.0
    }
}

/// Independent Audit transaction owner over a host-supplied pool.
/// Does not run migrations or close the host pool. Message borrowing keeps its original owner.
#[derive(Clone)]
pub struct PgAudit {
    pub(crate) pool: PgPool,
    pub(crate) integrity: Integrity,
    #[cfg(feature = "integration")]
    fault: std::sync::Arc<std::sync::atomic::AtomicU8>,
}
impl PgAudit {
    /// Validate the actual schema and runtime role, without migration or session mutation.
    pub async fn new<T: ExecutionTimer>(
        pool: PgPool,
        integrity: Integrity,
        control: &Control<'_, T>,
    ) -> Result<Self, Error> {
        control
            .run(Stage::Acquire, async {
                let connection = pool.acquire().await?;
                let mut lease = Lease::new(connection);
                probe::validate(&mut lease.connection).await?;
                lease.confirmed = true;
                Ok(())
            })
            .await?;
        Ok(Self {
            pool,
            integrity,
            #[cfg(feature = "integration")]
            fault: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
        })
    }
    /// Assign recording time from PostgreSQL and return exact retry bytes, not commit evidence.
    /// Preserve this request, including its timestamp, after an uncertain append.
    pub async fn prepare<T: ExecutionTimer>(
        &self,
        event: AuditEventV1,
        control: &Control<'_, T>,
    ) -> Result<PreparedAuditV1, Error> {
        control
            .run(Stage::Operation, async {
                let mut lease = Lease::new(self.pool.acquire().await?);
                let seconds: i64 = sqlx::query_scalar(
                    "SELECT floor(extract(epoch FROM clock_timestamp()))::bigint",
                )
                .fetch_one(&mut *lease.connection)
                .await?;
                let recorded = Timepoint::try_from(seconds).map_err(|_| Error::StorageContract)?;
                let prepared = rss_audit_core::prepare(event, recorded)?;
                lease.confirmed = true;
                Ok(prepared)
            })
            .await
    }
    /// Append and settle independently. Retry the unchanged request after commit-unknown.
    pub async fn append<T: ExecutionTimer>(
        &self,
        request: &PreparedAuditV1,
        control: &Control<'_, T>,
    ) -> LocalTxAttempt<Committed<StagedAppend>, Error> {
        let request = request.clone();
        audit_only(
            self.local_tx(
                request.append_request().ledger().tenant(),
                control,
                move |tx| Box::pin(async move { tx.append(&request).await }),
            )
            .await,
        )
    }
    /// Read a bounded ordinary page, explicitly without a ledger authentication claim.
    pub async fn read_page<T: ExecutionTimer>(
        &self,
        cursor: Cursor,
        limit: ReadLimit,
        control: &Control<'_, T>,
    ) -> LocalTxAttempt<Committed<Page>, Error> {
        audit_only(
            self.local_tx(cursor.tenant(), control, move |tx| {
                Box::pin(async move { tx.read_page(cursor, limit).await })
            })
            .await,
        )
    }
    /// Authenticate a ledger window with its distinct sequence coordinate and encoded-byte budget.
    /// Same-database predecessors are not external checkpoints or proof against tail truncation.
    #[cfg(feature = "ledger")]
    pub async fn read_verified<T: ExecutionTimer>(
        &self,
        tenant: TenantId,
        start: rss_ledger::Sequence,
        limit: rss_ledger_postgres::ReadLimit,
        control: &Control<'_, T>,
    ) -> LocalTxAttempt<Committed<rss_audit_core::VerifiedAuditWindow>, Error> {
        audit_only(
            self.local_tx(tenant, control, move |tx| {
                Box::pin(async move { tx.verified(start, limit).await })
            })
            .await,
        )
    }
    /// Execute Audit and trusted business SQL in one tenant-bound transaction.
    /// Every stage inherits the same absolute deadline; unconfirmed leases are retired.
    /// The callback's original error is retained in `TransactionError::Operation`.
    /// An unacknowledged rollback additionally retains its separate settlement failure.
    ///
    /// ```compile_fail
    /// use rss_audit_postgres::{AuditTransaction, Error};
    /// use rss_request_context::ExecutionTimer;
    /// async fn escape<T: ExecutionTimer>(tx: &mut AuditTransaction<'_, '_, '_, T>) {
    ///     let connection = tx.with_connection(|c| Box::pin(async move { Ok::<_, Error>(c) })).await;
    /// }
    /// ```
    pub async fn local_tx<T: ExecutionTimer, R: Send, E: Send, F>(
        &self,
        tenant: TenantId,
        control: &Control<'_, T>,
        operation: F,
    ) -> LocalTxAttempt<Committed<R>, TransactionError<E>>
    where
        F: for<'a> FnOnce(&'a mut AuditTransaction<'_, '_, '_, T>) -> BoxFuture<'a, Result<R, E>>
            + Send,
    {
        let connection = match control
            .run(Stage::Acquire, async { Ok(self.pool.acquire().await?) })
            .await
        {
            Ok(c) => c,
            Err(e) => return LocalTxAttempt::not_started(TransactionError::Audit(e)),
        };
        let mut lease = Lease::new(connection);
        let mut tx = match control
            .run(Stage::Begin, async { Ok(lease.connection.begin().await?) })
            .await
        {
            Ok(tx) => tx,
            Err(e) => return LocalTxAttempt::not_started(TransactionError::Audit(e)),
        };
        let body=control.run(Stage::Setup,async {
            let millis=control.remaining().as_millis().clamp(1,i32::MAX as u128).to_string();
            sqlx::query("SELECT set_config('rss.tenant_id',$1,true),set_config('statement_timeout',$2,true),set_config('lock_timeout',$2,true)")
                .bind(tenant.to_string()).bind(millis).execute(&mut *tx).await?;
            probe::validate(&mut tx).await
        }).await;
        let body = match body {
            Ok(()) => control
                .run(Stage::Operation, async {
                    Ok(operation(&mut AuditTransaction {
                        tx: &mut tx,
                        control,
                        integrity: &self.integrity,
                        tenant,
                    })
                    .await)
                })
                .await
                .map_err(TransactionError::Audit)
                .and_then(|result| result.map_err(TransactionError::Operation)),
            Err(e) => Err(TransactionError::Audit(e)),
        };
        #[cfg(feature = "integration")]
        let fault = self.fault.swap(0, std::sync::atomic::Ordering::SeqCst);
        match body {
            Ok(value) => {
                let settled = control
                    .run(Stage::Commit, async {
                        #[cfg(feature = "integration")]
                        if fault == PgFault::BeforeCommitPending as u8 {
                            std::future::pending::<()>().await;
                        }
                        tx.commit().await?;
                        #[cfg(feature = "integration")]
                        if fault == PgFault::CommitUnknownAfterAck as u8 {
                            return Err(Error::Deadline(Stage::Commit));
                        }
                        Ok(())
                    })
                    .await;
                match settled {
                    Ok(()) => {
                        lease.confirmed = true;
                        LocalTxAttempt::committed(Committed(value))
                    }
                    Err(e) => LocalTxAttempt::commit_unknown(TransactionError::Audit(e)),
                }
            }
            Err(operation) => {
                let settled = control
                    .run(Stage::Rollback, async {
                        tx.rollback().await?;
                        #[cfg(feature = "integration")]
                        if fault == PgFault::RollbackFailedAfterAck as u8 {
                            return Err(Error::Deadline(Stage::Rollback));
                        }
                        Ok(())
                    })
                    .await;
                match settled {
                    Ok(()) => {
                        lease.confirmed = true;
                        LocalTxAttempt::rolled_back(operation)
                    }
                    Err(settlement) => {
                        LocalTxAttempt::rollback_failed(TransactionError::Rollback {
                            operation: Box::new(operation),
                            settlement,
                        })
                    }
                }
            }
        }
    }
    /// Inject one fixture-owned settlement fault. Not present in production feature sets.
    #[cfg(feature = "integration")]
    pub fn inject_next_fault(&self, fault: PgFault) {
        self.fault
            .store(fault as u8, std::sync::atomic::Ordering::SeqCst);
    }
}
struct Lease {
    connection: PoolConnection<Postgres>,
    confirmed: bool,
}
impl Lease {
    fn new(connection: PoolConnection<Postgres>) -> Self {
        Self {
            connection,
            confirmed: false,
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        if !self.confirmed {
            self.connection.close_on_drop();
        }
    }
}
/// Test-only faults after real protocol acknowledgements or before sending COMMIT.
#[cfg(feature = "integration")]
#[derive(Clone, Copy)]
#[repr(u8)]
pub enum PgFault {
    /// Durable commit succeeded, but suppress its acknowledgement.
    CommitUnknownAfterAck = 1,
    /// Pause before sending COMMIT until interrupted by the host control.
    BeforeCommitPending = 2,
    /// Rollback succeeded, but suppress its acknowledgement.
    RollbackFailedAfterAck = 3,
}

fn audit_only<R>(
    attempt: LocalTxAttempt<Committed<R>, TransactionError<Error>>,
) -> LocalTxAttempt<Committed<R>, Error> {
    attempt.fold(
        LocalTxAttempt::committed,
        |e| LocalTxAttempt::not_started(e.into_audit()),
        |e| LocalTxAttempt::rolled_back(e.into_audit()),
        |e| LocalTxAttempt::rollback_failed(e.into_audit()),
        |e| LocalTxAttempt::commit_unknown(e.into_audit()),
        |e| LocalTxAttempt::fenced(e.into_audit()),
    )
}
