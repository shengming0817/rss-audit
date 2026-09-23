use crate::AuditQuery;
use rss_audit_core::PreparedAuditV1;
use rss_request_context::{Deadline, TenantId};
use tokio_util::sync::CancellationToken;

/// Host-owned per-request budget. The timer supplied to the router must share its time domain.
#[derive(Clone)]
pub struct AuditRequestBudget {
    pub(crate) deadline: Deadline,
    pub(crate) cancel: CancellationToken,
}
impl AuditRequestBudget {
    /// Observe the host's deadline and cancellation; the adapter never extends either.
    pub fn new(deadline: Deadline, cancellation: &CancellationToken) -> Self {
        Self {
            deadline,
            cancel: cancellation.child_token(),
        }
    }
    /// Original absolute cutoff.
    pub const fn deadline(&self) -> Deadline {
        self.deadline
    }
    /// Observe host cancellation without exposing its trigger.
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }
}
/// Explicit per-request choice, owned by product policy.
pub enum SelfAudit {
    /// Product policy does not require an additional query record.
    NotRequired,
    /// Exact prepared query-attempt record. Host must durably preserve these bytes before
    /// dispatch, and recover uncertainty without changing the event ID or recording time.
    /// Neither this value nor a database commit proves delivery to the HTTP client.
    Required(PreparedAuditV1),
}
/// Authorization from trusted host evidence, not from request navigation or headers.
pub struct QueryGrant {
    pub(crate) tenant: TenantId,
    pub(crate) audit: SelfAudit,
}
/// The host supplied inconsistent query-audit authority.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("inconsistent audit query grant")]
pub struct InvalidGrant;
impl QueryGrant {
    /// Bind the authenticated tenant to an explicit audit choice. The host is the authority
    /// for authentication, session freshness, authorization and preservation of retry bytes.
    pub fn new(tenant: TenantId, audit: SelfAudit) -> Result<Self, InvalidGrant> {
        if let SelfAudit::Required(request) = &audit
            && request.append_request().ledger().tenant() != tenant
        {
            return Err(InvalidGrant);
        }
        Ok(Self { tenant, audit })
    }
}
/// Safe policy rejection; arbitrary provider/credential strings cannot enter it.
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum QueryPolicyError {
    /// The session is absent, invalid or no longer live.
    #[error("authentication required")]
    Unauthenticated,
    /// The live session lacks tenant-query permission.
    #[error("audit query denied")]
    Denied,
    /// The policy cannot make a trustworthy decision.
    #[error("audit query policy unavailable")]
    Unavailable,
}
/// Required host policy; no default implementation or implicit allow path.
/// S is host-owned request-local authenticated evidence, never a deserialized wire identity.
/// Check its current validity and authorize the entire tenant query on every call. This is a
/// bounded synchronous decision: authenticate/prepare/persist outside this callback, without
/// resetting the incoming budget. Do not perform blocking I/O or interpret cursor tenant as authority.
pub trait AuditQueryPolicy<S>: Send + Sync + 'static {
    /// Grant the current authenticated tenant and an explicit query-audit choice.
    fn authorize(
        &self,
        session: &S,
        query: &AuditQuery,
        budget: &AuditRequestBudget,
    ) -> Result<QueryGrant, QueryPolicyError>;
}
