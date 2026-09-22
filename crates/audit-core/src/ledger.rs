use crate::{AuditEventV1, DecodedAuditV1, Error, EventId, SourceId, codec};
use rss_contract::Timepoint;
use rss_ledger::{
    AppendRequest, Authenticator, ChainId, Entry, LedgerId, RecordId, Sequence, Verification,
};
use rss_request_context::TenantId;

/// Fixed Audit V1 chain identity. Every tenant has one V1 audit sequence.
pub const AUDIT_CHAIN_ID: &str = "rss.audit.v1";

fn audit_record_id(source: &SourceId, event: &EventId) -> Result<RecordId, Error> {
    Ok(RecordId::parse(&format!(
        "v1:{}:{}",
        source.as_str(),
        event.as_str()
    ))?)
}

/// Canonical Audit V1 bytes lowered to a ledger append request.
///
/// Preparation performs no provider I/O and is never durable-commit evidence.
pub struct PreparedAuditV1 {
    request: AppendRequest,
}

impl PreparedAuditV1 {
    /// Exact ledger request to stage. Preserve it unchanged after commit-unknown.
    #[must_use]
    pub const fn append_request(&self) -> &AppendRequest {
        &self.request
    }

    /// Exact canonical Audit V1 bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        self.request.payload()
    }

    /// Compare a returned ledger entry to this exact request.
    #[must_use]
    pub fn matches_entry(&self, entry: &Entry) -> bool {
        entry.matches(&self.request)
    }
}

impl std::fmt::Debug for PreparedAuditV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedAuditV1([redacted])")
    }
}

/// Assign recording time and produce the one canonical ledger request.
///
/// The caller supplying `recorded_at` is responsible for using the recorder/provider authority.
/// This function performs no I/O and returns no staged or committed evidence.
pub fn prepare(event: AuditEventV1, recorded_at: Timepoint) -> Result<PreparedAuditV1, Error> {
    let canonical = codec::encode(&event, recorded_at)?;
    let record_id = audit_record_id(
        event.identity().source().source_id(),
        event.identity().event_id(),
    )?;
    let chain = ChainId::parse(AUDIT_CHAIN_ID)?;
    let ledger = LedgerId::new(event.identity().tenant(), chain);
    let request = AppendRequest::new(ledger, record_id, canonical)?;
    Ok(PreparedAuditV1 { request })
}

/// One authenticated Audit record and its ledger sequence.
///
/// Authentication is limited to the supplied window and does not prove durable commit or absence
/// of truncation.
pub struct VerifiedAuditEntryV1 {
    sequence: Sequence,
    record: DecodedAuditV1,
}

impl VerifiedAuditEntryV1 {
    /// Ledger position in the verified window.
    #[must_use]
    pub const fn sequence(&self) -> Sequence {
        self.sequence
    }

    /// Decoded authenticated record.
    #[must_use]
    pub const fn record(&self) -> &DecodedAuditV1 {
        &self.record
    }
}

impl std::fmt::Debug for VerifiedAuditEntryV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedAuditEntryV1")
            .field("sequence", &self.sequence)
            .finish_non_exhaustive()
    }
}

/// Authenticated Audit records for exactly one supplied ledger window.
pub struct VerifiedAuditWindow {
    ledger: Verification,
    records: Vec<VerifiedAuditEntryV1>,
}

impl VerifiedAuditWindow {
    /// Underlying limited ledger verification result.
    #[must_use]
    pub const fn ledger_verification(&self) -> &Verification {
        &self.ledger
    }

    /// Audit records corresponding to the verified entries.
    #[must_use]
    pub fn records(&self) -> &[VerifiedAuditEntryV1] {
        &self.records
    }
}

impl std::fmt::Debug for VerifiedAuditWindow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedAuditWindow")
            .field("ledger", &self.ledger)
            .field("record_count", &self.records.len())
            .finish()
    }
}

/// Authenticate and decode one exact Audit ledger window.
///
/// The predecessor is authenticated but remains caller-supplied; a same-database anchor is not an
/// external checkpoint. Empty input proves zero records, not an empty ledger.
pub fn verify_window(
    authenticator: &Authenticator,
    tenant: TenantId,
    predecessor: Option<&Entry>,
    entries: &[Entry],
) -> Result<VerifiedAuditWindow, Error> {
    let ledger_id = LedgerId::new(tenant, ChainId::parse(AUDIT_CHAIN_ID)?);
    let ledger = authenticator.verify_window(&ledger_id, predecessor, entries)?;
    let mut records = Vec::with_capacity(entries.len());
    for entry in entries {
        let record = codec::decode_untrusted(entry.payload())?;
        let identity = record.event().identity();
        if identity.tenant() != tenant {
            return Err(Error::IdentityMismatch);
        }
        let expected = audit_record_id(identity.source().source_id(), identity.event_id())?;
        if entry.record_id() != &expected {
            return Err(Error::IdentityMismatch);
        }
        records.push(VerifiedAuditEntryV1 {
            sequence: entry.sequence(),
            record,
        });
    }
    Ok(VerifiedAuditWindow { ledger, records })
}
