use crate::Error;
use rss_request_context::{Deadline, ExecutionTimer};
use rss_transactional_messaging::transaction::LocalTxDeadlineStage;
use std::{future::Future, time::Duration};
use tokio_util::sync::CancellationToken;

/// One caller-owned absolute budget through acquisition, operation and settlement.
pub struct Control<'a, T> {
    pub(crate) timer: &'a T,
    pub(crate) deadline: Deadline,
    pub(crate) cancel: &'a CancellationToken,
}
impl<'a, T: ExecutionTimer> Control<'a, T> {
    /// Bind a monotonic timer, its absolute cutoff and host cancellation.
    pub const fn new(timer: &'a T, deadline: Deadline, cancel: &'a CancellationToken) -> Self {
        Self {
            timer,
            deadline,
            cancel,
        }
    }
    /// Remaining time without resetting the cutoff.
    pub fn remaining(&self) -> Duration {
        self.deadline
            .remaining(self.timer.now())
            .unwrap_or_default()
    }
    pub(crate) fn check(&self, stage: LocalTxDeadlineStage) -> Result<(), Error> {
        if self.cancel.is_cancelled() {
            Err(Error::Cancelled(stage))
        } else if self.remaining().is_zero() {
            Err(Error::Deadline(stage))
        } else {
            Ok(())
        }
    }
    pub(crate) async fn run<R>(
        &self,
        stage: LocalTxDeadlineStage,
        future: impl Future<Output = Result<R, Error>>,
    ) -> Result<R, Error> {
        self.check(stage)?;
        tokio::select! { biased;
            () = self.cancel.cancelled() => Err(Error::Cancelled(stage)),
            () = self.timer.sleep_until(self.deadline) => Err(Error::Deadline(stage)),
            value = future => value,
        }
    }
}

#[cfg(feature = "ledger")]
pub(crate) struct LedgerClock<'a, T>(pub &'a T, pub std::time::Instant);
#[cfg(feature = "ledger")]
impl<T: ExecutionTimer> rss_ledger_postgres::Timer for LedgerClock<'_, T> {
    fn now(&self) -> Duration {
        self.0.now().saturating_duration_since(self.1)
    }
    async fn sleep_until(&self, cutoff: Duration) {
        self.0.sleep_until(Deadline::at(self.1 + cutoff)).await;
    }
}
