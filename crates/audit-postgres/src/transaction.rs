use crate::{Control, Error, Integrity, StagedAppend, repository};
use futures::future::BoxFuture;
use rss_audit_core::{AuditEventV1, PreparedAuditV1, RecordIdentity};
use rss_request_context::{ExecutionTimer, TenantId};
use sqlx::{PgConnection, Postgres, Transaction};

/// Tenant-bound read access. PostgreSQL enforces read-only mode in a read transaction.
/// The enclosing owner alone settles; transaction/session control is forbidden in raw SQL.
///
/// ```compile_fail
/// use rss_audit_postgres::ReadAuditTransaction;
/// use rss_audit_core::PreparedAuditV1;
/// use rss_request_context::ExecutionTimer;
/// async fn append<T: ExecutionTimer>(tx: &mut ReadAuditTransaction<'_, '_, '_, T>, p: &PreparedAuditV1) {
///     tx.append(p).await;
/// }
/// ```
pub struct ReadAuditTransaction<'a, 'db, 'control, T> {
    pub(crate) tx: &'a mut Transaction<'db, Postgres>,
    pub(crate) control: &'control Control<'control, T>,
    pub(crate) integrity: &'control Integrity,
    pub(crate) tenant: TenantId,
}
impl<T: ExecutionTimer> ReadAuditTransaction<'_, '_, '_, T> {
    /// Fixed tenant of this transaction.
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant
    }
    /// Prepare exact bytes using PostgreSQL time on this connection and budget.
    pub async fn prepare(&mut self, event: AuditEventV1) -> Result<PreparedAuditV1, Error> {
        if event.identity().tenant() != self.tenant {
            return Err(Error::ScopeMismatch);
        }
        self.control
            .run(
                rss_transactional_messaging::transaction::LocalTxDeadlineStage::Operation,
                repository::prepare(self.tx, event, Some(self.tenant)),
            )
            .await
    }
    /// Read exact stored bytes. Absence alone is not rollback evidence.
    pub async fn find(
        &mut self,
        identity: &RecordIdentity,
    ) -> Result<Option<crate::Record>, Error> {
        if identity.tenant() != self.tenant {
            return Err(Error::ScopeMismatch);
        }
        self.control
            .run(
                rss_transactional_messaging::transaction::LocalTxDeadlineStage::Operation,
                repository::find(self.tx, identity),
            )
            .await
    }
    /// Read within this transaction's tenant and the first page's fixed upper bound.
    pub async fn read_page(
        &mut self,
        cursor: crate::Cursor,
        limit: crate::ReadLimit,
    ) -> Result<crate::Page, Error> {
        self.control
            .check(rss_transactional_messaging::transaction::LocalTxDeadlineStage::Operation)?;
        if cursor.tenant() != self.tenant {
            return Err(Error::ScopeMismatch);
        }
        repository::page(self.tx, cursor, limit).await
    }
    /// Borrow trusted SQL; transaction control and tenant/session mutation are forbidden.
    /// The connection cannot escape the callback. This is not a SQL sandbox.
    /// The callback's error type is returned unchanged, without formatting bounds.
    pub async fn with_connection<R: Send, E: Send, F>(&mut self, operation: F) -> Result<R, E>
    where
        F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<R, E>> + Send,
    {
        self.with_connection_context(&mut (), move |_, c| operation(c))
            .await
    }
    /// Borrow trusted SQL and scoped host inputs together; neither can escape the callback.
    /// This has the same SQL/session restrictions as `with_connection`.
    ///
    /// ```compile_fail
    /// use rss_audit_postgres::{ReadAuditTransaction, Error};
    /// use rss_request_context::ExecutionTimer;
    /// async fn escape<T: ExecutionTimer>(tx: &mut ReadAuditTransaction<'_, '_, '_, T>) {
    ///     let mut context = String::new();
    ///     let escaped = tx.with_connection_context(&mut context, |context, connection| {
    ///         Box::pin(async move { Ok::<_, Error>((context, connection)) })
    ///     }).await;
    /// }
    /// ```
    pub async fn with_connection_context<R: Send, E: Send, C: Send, F>(
        &mut self,
        context: &mut C,
        operation: F,
    ) -> Result<R, E>
    where
        F: for<'c> FnOnce(&'c mut C, &'c mut PgConnection) -> BoxFuture<'c, Result<R, E>> + Send,
    {
        operation(context, self.tx).await
    }
    #[cfg(feature = "ledger")]
    pub(crate) async fn verified(
        &mut self,
        start: rss_ledger::Sequence,
        limit: rss_ledger_postgres::ReadLimit,
    ) -> Result<rss_audit_core::VerifiedAuditWindow, Error> {
        let Integrity::Ledger(auth) = self.integrity else {
            return Err(Error::IntegrityRequired);
        };
        crate::probe::tenant(self.tx, self.tenant).await?;
        let id = crate::runtime::ledger_id(self.tenant)?;
        let clock = crate::control::LedgerClock(self.control.timer, self.control.timer.now());
        let budget = clock.budget(self.control);
        let window = rss_ledger_postgres::read_window_in_transaction(
            self.tx, auth, &id, start, limit, &budget,
        )
        .await?;
        for entry in window.entries() {
            let decoded = rss_audit_core::decode_untrusted(entry.payload())?;
            let identity = decoded.event().identity();
            // Compare metadata in PostgreSQL without fetching a second payload: the
            // ledger window has already charged these bytes against its read budget.
            let matches: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM rss_audit.records WHERE tenant_id=$1::uuid \
                 AND ledger_sequence=$2 AND canonical=$3 AND source_id=$4 \
                 AND event_id=$5 AND recorded_at=$6)",
            )
            .bind(self.tenant.to_string())
            .bind(i64::try_from(entry.sequence().get()).map_err(|_| Error::StorageContract)?)
            .bind(entry.payload())
            .bind(identity.source().source_id().as_str())
            .bind(identity.event_id().as_str())
            .bind(decoded.recorded_at().unix_seconds())
            .fetch_one(&mut **self.tx)
            .await?;
            if !matches {
                return Err(Error::StorageContract);
            }
        }
        Ok(rss_audit_core::verify_window(
            auth,
            self.tenant,
            window.predecessor(),
            window.entries(),
        )?)
    }
}

/// Tenant-bound write access, handed to the callback after Audit and optional Ledger locks.
/// Read operations share the same connection, live admission and absolute operation cutoff.
pub struct WriteAuditTransaction<'a, 'db, 'control, T> {
    pub(crate) read: ReadAuditTransaction<'a, 'db, 'control, T>,
}
impl<'a, 'db, 'control, T> std::ops::Deref for WriteAuditTransaction<'a, 'db, 'control, T> {
    type Target = ReadAuditTransaction<'a, 'db, 'control, T>;
    fn deref(&self) -> &Self::Target {
        &self.read
    }
}
impl<T> std::ops::DerefMut for WriteAuditTransaction<'_, '_, '_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.read
    }
}
impl<T: ExecutionTimer> WriteAuditTransaction<'_, '_, '_, T> {
    /// Acquire Audit then optional ledger locks before deriving business facts.
    /// Does not append an event; only the original owner can settle this transaction.
    pub(crate) async fn lock_head(&mut self) -> Result<(), Error> {
        self.read
            .control
            .run(
                rss_transactional_messaging::transaction::LocalTxDeadlineStage::Operation,
                repository::lock_head(self.read.tx, self.read.tenant),
            )
            .await?;
        #[cfg(feature = "ledger")]
        if let Integrity::Ledger(auth) = self.read.integrity {
            let clock =
                crate::control::LedgerClock(self.read.control.timer, self.read.control.timer.now());
            let budget = clock.budget(self.read.control);
            rss_ledger_postgres::lock_head_in_transaction(
                self.read.tx,
                auth,
                &crate::runtime::ledger_id(self.read.tenant)?,
                &budget,
            )
            .await?;
        }
        Ok(())
    }
    /// Stage exact canonical bytes. Propagate any error to the enclosing owner.
    /// Acquire Audit before ledger before business/outbox locks.
    pub async fn append(&mut self, request: &PreparedAuditV1) -> Result<StagedAppend, Error> {
        self.read
            .control
            .check(rss_transactional_messaging::transaction::LocalTxDeadlineStage::Operation)?;
        if request.append_request().ledger().tenant() != self.read.tenant {
            return Err(Error::ScopeMismatch);
        }
        let existing =
            repository::reserve(self.read.tx, request, self.read.integrity.is_ledger()).await?;
        let ledger = match self.read.integrity {
            Integrity::Plain => None,
            #[cfg(feature = "ledger")]
            Integrity::Ledger(auth) => {
                let clock = crate::control::LedgerClock(
                    self.read.control.timer,
                    self.read.control.timer.now(),
                );
                let budget = clock.budget(self.read.control);
                let staged = rss_ledger_postgres::append_in_transaction(
                    self.read.tx,
                    auth,
                    request.append_request(),
                    &budget,
                )
                .await?;
                Some((staged.entry().sequence().get(), staged.inserted()))
            }
        };
        repository::finish(self.read.tx, request, existing, ledger).await
    }
}
