use rss_redact::RedactedSource;
use rss_transactional_messaging::transaction::LocalTxDeadlineStage;

/// Closed live admission categories without database identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionViolation {
    /// Missing or changed durable schema.
    Schema,
    /// Unsafe runtime or owner role.
    Role,
    /// Excessive, missing or delegated access.
    Permissions,
    /// Row-level isolation differs from the contract.
    Rls,
    /// Definer function differs from the migration.
    Functions,
    /// Persisted column or constraint shape differs.
    Shape,
}

/// Operation failure. Settlement remains a separate canonical `LocalTxAttempt`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Live schema or role admission failed.
    #[error("audit admission violation: {0:?}")]
    Admission(AdmissionViolation),
    /// Caller supplied an invalid cursor or bound.
    #[error("invalid audit read bound")]
    InvalidBound,
    /// The actual transaction tenant differs from the requested tenant.
    #[error("audit tenant mismatch")]
    ScopeMismatch,
    /// Stable identity has different bytes or integrity mode.
    #[error("audit identity conflict")]
    Conflict,
    /// Stored data violates the adapter contract.
    #[error("invalid audit storage contract")]
    StorageContract,
    /// The complete selected page exceeds the canonical byte budget; no partial page is returned.
    #[error("audit read byte budget exceeded")]
    ReadBudgetExceeded,
    /// A ledger-only operation was requested from an explicitly plain owner.
    #[error("audit ledger integrity is not enabled")]
    IntegrityRequired,
    /// Host business operation requests rollback.
    #[error("audit operation rejected")]
    Rejected,
    /// Absolute deadline expired at the named stage.
    #[error("audit deadline elapsed")]
    Deadline(LocalTxDeadlineStage),
    /// Host cancellation was observed at the named stage.
    #[error("audit operation cancelled")]
    Cancelled(LocalTxDeadlineStage),
    /// Invalid canonical audit protocol input.
    #[error(transparent)]
    Protocol(#[from] rss_audit_core::Error),
    /// Ledger integrity failures never downgrade to plain persistence.
    #[cfg(feature = "ledger")]
    #[error(transparent)]
    Ledger(#[from] rss_ledger_postgres::Error),
    /// Enclosing message owner's original classified error, including ownership loss.
    #[cfg(feature = "messaging")]
    #[error(transparent)]
    Messaging(#[from] rss_transactional_messaging_postgres::PgError),
    /// Provider error text is not exposed by formatting or source traversal.
    #[error("audit storage unavailable")]
    Storage(#[source] RedactedSource),
    /// A rollback was attempted but not acknowledged; retain both failures.
    #[error("audit rollback unconfirmed")]
    Rollback {
        /// Original operation failure.
        operation: Box<Error>,
        /// Rollback settlement failure.
        settlement: Box<Error>,
    },
}

impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        match error.as_database_error().and_then(|e| e.code()).as_deref() {
            Some("PA001") => Self::ScopeMismatch,
            Some("PA002" | "23505" | "23514" | "23503") => Self::StorageContract,
            _ => Self::Storage(RedactedSource::new(error)),
        }
    }
}
