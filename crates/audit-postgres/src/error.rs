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

/// Closed infrastructure retry classification; not transaction settlement evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageFailure {
    /// Connection interruption, resource contention or cancellation may recover.
    Transient,
    /// Permissions, schema, invalid queries or closed resources require intervention.
    Permanent,
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
    Storage {
        /// Safe classification; the host decides whether to stop or retry.
        kind: StorageFailure,
        /// Opaque diagnostics, never exposed through formatting or source traversal.
        #[source]
        source: RedactedSource,
    },
    /// Rollback was not acknowledged; retain the operation and settlement failures.
    #[error("audit rollback unconfirmed")]
    Rollback {
        /// Original operation failure.
        operation: Box<Error>,
        /// Rollback settlement failure.
        settlement: Box<Error>,
    },
}

/// Failure of an Audit-owned transaction with the host's original operation error.
/// Settlement authority remains in `LocalTxAttempt`, never in this error value.
/// Formatting and source traversal do not expose the host error; match `Operation`
/// explicitly to recover its typed reason and host-owned retry classification.
pub enum TransactionError<E> {
    /// Audit admission, control or provider failure.
    Audit(Error),
    /// The callback's original error, without formatting or type erasure.
    Operation(E),
    /// Rollback was not acknowledged; preserve both the original cause and cleanup error.
    Rollback {
        /// Original callback or Audit failure.
        operation: Box<Self>,
        /// Rollback admission or execution failure.
        settlement: Error,
    },
}

impl<E> std::fmt::Display for TransactionError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Audit(_) => "audit transaction failed",
            Self::Operation(_) => "host operation failed",
            Self::Rollback { .. } => "audit rollback unconfirmed",
        })
    }
}
impl<E> std::fmt::Debug for TransactionError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Audit(error) => f.debug_tuple("Audit").field(error).finish(),
            Self::Operation(_) => f.write_str("Operation([redacted])"),
            Self::Rollback {
                operation,
                settlement,
            } => f
                .debug_struct("Rollback")
                .field("operation", operation)
                .field("settlement", settlement)
                .finish(),
        }
    }
}
impl<E> std::error::Error for TransactionError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Audit(error) => Some(error),
            Self::Operation(_) => None,
            Self::Rollback { settlement, .. } => Some(settlement),
        }
    }
}
impl TransactionError<Error> {
    // Standalone append/read callbacks contain only Audit errors, never host errors.
    pub(crate) fn into_audit(self) -> Error {
        match self {
            Self::Audit(error) | Self::Operation(error) => error,
            Self::Rollback {
                operation,
                settlement,
            } => Error::Rollback {
                operation: Box::new(operation.into_audit()),
                settlement: Box::new(settlement),
            },
        }
    }
}

impl From<sqlx::Error> for Error {
    fn from(error: sqlx::Error) -> Self {
        match error.as_database_error().and_then(|e| e.code()).as_deref() {
            Some("PA001") => Self::ScopeMismatch,
            Some("PA002" | "23505" | "23514" | "23503") => Self::StorageContract,
            _ => {
                let kind = match &error {
                    sqlx::Error::Database(db) => db
                        .code()
                        .map_or(StorageFailure::Permanent, |code| database_failure(&code)),
                    sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut | sqlx::Error::WorkerCrashed => {
                        StorageFailure::Transient
                    }
                    _ => StorageFailure::Permanent,
                };
                Self::Storage {
                    kind,
                    source: RedactedSource::new(error),
                }
            }
        }
    }
}

// PostgreSQL SQLSTATE classes; unknown permanent failures must not become endless retries.
fn database_failure(code: &str) -> StorageFailure {
    if code.starts_with("08")
        || code.starts_with("40")
        || code.starts_with("53")
        || matches!(code, "55P03" | "57014" | "57P01" | "57P02" | "57P03")
    {
        StorageFailure::Transient
    } else {
        StorageFailure::Permanent
    }
}

#[cfg(test)]
mod storage_tests {
    use super::*;
    #[test]
    fn sqlstates_preserve_retryability_without_diagnostics() {
        for code in ["42501", "42P01", "42883", "22012", "XX000"] {
            assert_eq!(database_failure(code), StorageFailure::Permanent);
        }
        for code in [
            "08006", "40001", "40P01", "53300", "55P03", "57014", "57P01",
        ] {
            assert_eq!(database_failure(code), StorageFailure::Transient);
        }
    }
}
