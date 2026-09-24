use crate::{Error, Integrity, PgAudit, StagedAppend, repository};
use rss_audit_core::PreparedAuditV1;
use rss_redact::RedactedSource;
use rss_transactional_messaging::error::MessagingErrorKind;
use rss_transactional_messaging_postgres::{PgError, PgTransaction};

impl PgAudit {
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
