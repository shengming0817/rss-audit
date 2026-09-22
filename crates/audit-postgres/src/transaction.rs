use crate::{Control, Error, Integrity, StagedAppend, repository};
use futures::future::BoxFuture;
use rss_audit_core::PreparedAuditV1;
use rss_request_context::{ExecutionTimer, TenantId};
use sqlx::{PgConnection, Postgres, Transaction};

/// Tenant-bound trusted business transaction. Only its enclosing owner can settle it.
pub struct AuditTransaction<'a, 'db, 'control, T> {
    pub(crate) tx: &'a mut Transaction<'db, Postgres>,
    pub(crate) control: &'control Control<'control, T>,
    pub(crate) integrity: &'control Integrity,
    pub(crate) tenant: TenantId,
}
impl<T: ExecutionTimer> AuditTransaction<'_, '_, '_, T> {
    /// Fixed tenant of this transaction.
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant
    }
    /// Stage exact canonical bytes. Propagate any error to the enclosing owner.
    /// Acquire Audit before ledger before business/outbox locks.
    pub async fn append(&mut self, request: &PreparedAuditV1) -> Result<StagedAppend, Error> {
        self.control
            .check(rss_transactional_messaging::transaction::LocalTxDeadlineStage::Operation)?;
        if request.append_request().ledger().tenant() != self.tenant {
            return Err(Error::ScopeMismatch);
        }
        let existing = repository::reserve(self.tx, request, self.integrity.is_ledger()).await?;
        let ledger = match self.integrity {
            Integrity::Plain => None,
            #[cfg(feature = "ledger")]
            Integrity::Ledger(auth) => {
                let clock =
                    crate::control::LedgerClock(self.control.timer, self.control.timer.now());
                let budget = rss_ledger_postgres::Control::new(
                    &clock,
                    self.control
                        .deadline
                        .instant()
                        .saturating_duration_since(clock.1),
                    self.control.cancel,
                );
                let staged = rss_ledger_postgres::append_in_transaction(
                    self.tx,
                    auth,
                    request.append_request(),
                    &budget,
                )
                .await?;
                Some((staged.entry().sequence().get(), staged.inserted()))
            }
        };
        repository::finish(self.tx, request, existing, ledger).await
    }
    /// Borrow trusted SQL; transaction control and tenant/session mutation are forbidden.
    /// The connection cannot escape the callback. This is not a SQL sandbox.
    pub async fn with_connection<R: Send, F>(&mut self, operation: F) -> Result<R, Error>
    where
        F: for<'c> FnOnce(&'c mut PgConnection) -> BoxFuture<'c, Result<R, Error>> + Send,
    {
        operation(self.tx).await
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
        let id = rss_ledger::LedgerId::new(
            self.tenant,
            rss_ledger::ChainId::parse(rss_audit_core::AUDIT_CHAIN_ID)
                .map_err(rss_audit_core::Error::from)?,
        );
        let clock = crate::control::LedgerClock(self.control.timer, self.control.timer.now());
        let budget = rss_ledger_postgres::Control::new(
            &clock,
            self.control
                .deadline
                .instant()
                .saturating_duration_since(clock.1),
            self.control.cancel,
        );
        let window = rss_ledger_postgres::read_window_in_transaction(
            self.tx, auth, &id, start, limit, &budget,
        )
        .await?;
        for entry in window.entries() {
            let matches:bool=sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM rss_audit.records WHERE tenant_id=$1::uuid AND ledger_sequence=$2 AND canonical=$3)")
                .bind(self.tenant.to_string()).bind(i64::try_from(entry.sequence().get()).map_err(|_|Error::StorageContract)?)
                .bind(entry.payload()).fetch_one(&mut **self.tx).await?;
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
