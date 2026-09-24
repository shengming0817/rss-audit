use axum::{
    Json,
    response::{IntoResponse, Response},
};
use rss_audit_postgres::{Committed, Error, TransactionError};
use rss_contract::{SafeError, SafeErrorCode};
use rss_transactional_messaging::transaction::LocalTxAttempt;
use std::sync::Arc;

type Attempt = LocalTxAttempt<(), TransactionError<Error>>;
/// Server-side diagnostic projection of the provider attempt, never commit authority.
/// Present only after a transaction result has been observed. It cannot survive a dropped
/// handler or prove that bytes reached the client. Nothing here is serialized to HTTP.
#[derive(Clone)]
pub struct QueryOutcome(Arc<Attempt>);
impl QueryOutcome {
    /// Remove this extension from the response and recover its canonical classified attempt.
    /// If the host cloned the extension, release those clones before retrying this operation.
    pub fn try_into_attempt(self) -> Result<LocalTxAttempt<(), TransactionError<Error>>, Self> {
        Arc::try_unwrap(self.0).map_err(Self)
    }
}
impl std::fmt::Debug for QueryOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("QueryOutcome([private])")
    }
}
pub(crate) fn safe(code: SafeErrorCode) -> Response {
    rss_axum::HttpError::from(SafeError::new(code)).into_response()
}
pub(crate) fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response
}
fn attach(mut response: Response, attempt: Attempt) -> Response {
    response
        .extensions_mut()
        .insert(QueryOutcome(Arc::new(attempt)));
    response
}
fn code(error: &TransactionError<Error>) -> SafeErrorCode {
    match error {
        TransactionError::Audit(e) | TransactionError::Operation(e) => match e {
            Error::InvalidBound => SafeErrorCode::InvalidInput,
            Error::Storage { .. }
            | Error::Deadline(_)
            | Error::Cancelled(_)
            | Error::Admission(_) => SafeErrorCode::Unavailable,
            _ => SafeErrorCode::Internal,
        },
        TransactionError::Rollback { .. } => SafeErrorCode::Unavailable,
    }
}
fn failed(
    error: TransactionError<Error>,
    classify: fn(TransactionError<Error>) -> Attempt,
    uncertain: bool,
) -> Response {
    let status = if uncertain {
        SafeErrorCode::Unavailable
    } else {
        code(&error)
    };
    attach(safe(status), classify(error))
}
pub(crate) fn settle(
    attempt: LocalTxAttempt<Committed<crate::dto::PageDto>, TransactionError<Error>>,
) -> Response {
    attempt.fold(
        |page| {
            attach(
                Json(page.into_value()).into_response(),
                LocalTxAttempt::committed(()),
            )
        },
        |e| failed(e, LocalTxAttempt::not_started, false),
        |e| failed(e, LocalTxAttempt::rolled_back, false),
        |e| failed(e, LocalTxAttempt::rollback_failed, true),
        |e| failed(e, LocalTxAttempt::commit_unknown, true),
        |e| failed(e, LocalTxAttempt::fenced, true),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_transactional_messaging::transaction::LocalTxDeadlineStage as Stage;
    #[tokio::test]
    async fn failures_preserve_classification_and_never_render_provider_text() -> anyhow::Result<()>
    {
        for (error, expected) in [
            (Error::InvalidBound, 400),
            (Error::ScopeMismatch, 500),
            (Error::StorageContract, 500),
            (Error::ReadBudgetExceeded, 500),
            (Error::Conflict, 500),
            (Error::Deadline(Stage::Operation), 503),
            (Error::Cancelled(Stage::Operation), 503),
            (
                Error::from(sqlx::Error::Protocol("credential-secret".into())),
                503,
            ),
        ] {
            let mut response = settle(LocalTxAttempt::rolled_back(TransactionError::Operation(
                error,
            )));
            assert_eq!(response.status().as_u16(), expected);
            let diagnostic = response
                .extensions_mut()
                .remove::<QueryOutcome>()
                .ok_or_else(|| anyhow::anyhow!("no outcome"))?;
            assert!(!format!("{diagnostic:?}").contains("credential-secret"));
            let copy = diagnostic.clone();
            let diagnostic = diagnostic
                .try_into_attempt()
                .err()
                .ok_or_else(|| anyhow::anyhow!("unexpected unique owner"))?;
            drop(copy);
            let attempt = diagnostic
                .try_into_attempt()
                .map_err(|_| anyhow::anyhow!("shared outcome"))?;
            assert!(attempt.fold(
                |_| false,
                |_| false,
                |_| true,
                |_| false,
                |_| false,
                |_| false
            ));
            let bytes = axum::body::to_bytes(response.into_body(), 4096).await?;
            assert!(!String::from_utf8(bytes.to_vec())?.contains("credential-secret"));
        }
        for (attempt, status) in [
            (
                LocalTxAttempt::not_started(TransactionError::Audit(Error::StorageContract)),
                500,
            ),
            (
                LocalTxAttempt::rollback_failed(TransactionError::Audit(Error::StorageContract)),
                503,
            ),
            (
                LocalTxAttempt::commit_unknown(TransactionError::Audit(Error::StorageContract)),
                503,
            ),
            (
                LocalTxAttempt::fenced(TransactionError::Audit(Error::StorageContract)),
                503,
            ),
        ] {
            assert_eq!(settle(attempt).status().as_u16(), status);
        }
        let error = TransactionError::Rollback {
            operation: Box::new(TransactionError::Operation(Error::StorageContract)),
            settlement: Error::Deadline(Stage::Rollback),
        };
        assert_eq!(code(&error), SafeErrorCode::Unavailable);
        Ok(())
    }
}
