use crate::{Error, Integrity, PgAudit, StagedAppend, repository};
use rss_audit_core::{PreparedAuditV1, RecordIdentity};
use rss_redact::RedactedSource;
use rss_transactional_messaging::error::MessagingErrorKind;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};

impl PgAudit {
    /// Acquire Audit and optional ledger locks before business/outbox locks.
    /// Borrows the original owner; no event, connection acquisition or settlement occurs.
    pub async fn lock_head_in(&self, tx: &mut PgTransaction<'_>) -> Result<(), Error> {
        let tenant = tx.tenant_id();
        tx.with_connection(move |c| {
            Box::pin(async move { Ok(repository::lock_head(c, tenant).await) })
        })
        .await??;
        #[cfg(feature = "ledger")]
        if let Integrity::Ledger(auth) = &self.integrity {
            rss_ledger_postgres::lock_head_in(
                tx,
                auth.clone(),
                &crate::runtime::ledger_id(tenant)?,
            )
            .await?;
        }
        Ok(())
    }
    /// Verify this actual message owner's role and storage during startup, before accepting work.
    /// Inherits its budget/connection and leaves all settlement to the owner.
    pub async fn validate_in(&self, tx: &mut PgTransaction<'_>) -> Result<(), Error> {
        tx.with_connection(|c| Box::pin(async move { Ok(crate::probe::validate(c).await) }))
            .await??;
        #[cfg(feature = "ledger")]
        if matches!(self.integrity, Integrity::Ledger(_)) {
            rss_ledger_postgres::validate_in(tx).await?;
        }
        Ok(())
    }
    /// Resolve and stage a fact on the message owner's READ COMMITTED transaction.
    /// Acquire `lock_head_in` before deriving business facts or reading product receipts;
    /// this method cannot retroactively protect earlier reads or business locks.
    /// The synchronous resolver returns exact bytes; product receipt rules remain caller-owned.
    pub async fn append_with_in<E, F>(
        &self,
        tx: &mut PgTransaction<'_>,
        identity: &RecordIdentity,
        resolve: F,
    ) -> Result<StagedAppend, E>
    where
        E: From<Error> + Send,
        F: FnOnce(Option<&crate::Record>, rss_contract::Timepoint) -> Result<PreparedAuditV1, E>
            + Send,
    {
        if identity.tenant() != tx.tenant_id() {
            return Err(Error::ScopeMismatch.into());
        }
        self.lock_head_in(tx).await?;
        let id = identity.clone();
        let (existing, now) = tx
            .with_connection(move |c| {
                Box::pin(async move { Ok(repository::resolution(c, &id).await) })
            })
            .await
            .map_err(Error::from)??;
        let request = resolve(existing.as_ref(), now)?;
        repository::check_resolved(
            identity,
            &request,
            existing.as_ref(),
            self.integrity.is_ledger(),
        )?;
        self.stage_in(tx, &request, existing).await.map_err(E::from)
    }
    /// Stage Audit in the message owner's actual connection and remaining budget.
    /// Does not acquire from this adapter's pool, change GUCs, begin or settle.
    /// Return failures to the message owner; only its receipt can authorize ACK.
    pub async fn append_in(
        &self,
        tx: &mut PgTransaction<'_>,
        request: &PreparedAuditV1,
    ) -> Result<StagedAppend, Error> {
        if request.append_request().ledger().tenant() != tx.tenant_id() {
            return Err(Error::ScopeMismatch);
        }
        let request_owned = request.clone();
        let ledger_enabled = self.integrity.is_ledger();
        let existing = tx
            .with_connection(move |c| {
                Box::pin(
                    async move { Ok(repository::reserve(c, &request_owned, ledger_enabled).await) },
                )
            })
            .await??;
        self.stage_in(tx, request, existing).await
    }
    async fn stage_in(
        &self,
        tx: &mut PgTransaction<'_>,
        request: &PreparedAuditV1,
        existing: Option<crate::Record>,
    ) -> Result<StagedAppend, Error> {
        let ledger = match &self.integrity {
            Integrity::Plain => None,
            #[cfg(feature = "ledger")]
            Integrity::Ledger(auth) => {
                let staged =
                    rss_ledger_postgres::append_in(tx, auth.clone(), request.append_request())
                        .await?;
                Some((staged.entry().sequence().get(), staged.inserted()))
            }
        };
        let request_owned = request.clone();
        tx.with_connection(move |c| {
            Box::pin(
                async move { Ok(repository::finish(c, &request_owned, existing, ledger).await) },
            )
        })
        .await?
    }
}

impl From<Error> for PgError {
    fn from(error: Error) -> Self {
        // Preserve the original message owner's closed classification without an error side channel.
        let kind = match error {
            Error::Messaging(original) => return original,
            #[cfg(feature = "ledger")]
            Error::Ledger(original) => return original.into(),
            Error::Conflict => MessagingErrorKind::Conflict,
            Error::Deadline(_) | Error::Cancelled(_) => MessagingErrorKind::DeadlineElapsed,
            Error::Admission(_) | Error::StorageContract => MessagingErrorKind::Invariant,
            Error::Storage {
                kind: crate::StorageFailure::Transient,
                ..
            }
            | Error::Rollback { .. } => MessagingErrorKind::Transient,
            Error::Storage {
                kind: crate::StorageFailure::Permanent,
                ..
            } => MessagingErrorKind::Permanent,
            Error::ScopeMismatch
            | Error::InvalidBound
            | Error::ReadBudgetExceeded
            | Error::IntegrityRequired
            | Error::Protocol(_) => MessagingErrorKind::Permanent,
        };
        Self::Operation {
            kind,
            source: RedactedSource::new(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_all_owner_classifications() {
        for kind in [
            MessagingErrorKind::Transient,
            MessagingErrorKind::Permanent,
            MessagingErrorKind::Conflict,
            MessagingErrorKind::OwnershipLost,
            MessagingErrorKind::Invariant,
            MessagingErrorKind::DeadlineElapsed,
        ] {
            let original = PgError::Operation {
                kind,
                source: RedactedSource::new(std::io::Error::other("sensitive provider text")),
            };
            let returned = PgError::from(Error::from(original));
            assert_eq!(returned.kind(), kind);
            assert!(!format!("{returned:?}").contains("sensitive"));
        }
    }
}
