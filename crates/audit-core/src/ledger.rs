use crate::{DecodedAuditV1, Error, EventId, PreparedAuditV1, SourceId, codec};
use rss_ledger::{
    AppendRequest, Authenticator, ChainId, Entry, LedgerId, RecordId, Sequence, Verification,
};
use rss_request_context::TenantId;

/// Fixed Audit V1 chain identity. Every tenant has one V1 audit sequence.
pub const AUDIT_CHAIN_ID: &str = "rss.audit.v1";

pub(crate) fn audit_record_id(source: &SourceId, event: &EventId) -> Result<RecordId, Error> {
    Ok(RecordId::parse(&format!(
        "v1:{}:{}",
        source.as_str(),
        event.as_str()
    ))?)
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

impl PreparedAuditV1 {
    /// Map this exact Audit record to its optional integrity chain. Not commit evidence.
    pub fn append_request(&self) -> Result<AppendRequest, Error> {
        let identity = self.identity();
        Ok(AppendRequest::new(
            LedgerId::new(identity.tenant(), ChainId::parse(AUDIT_CHAIN_ID)?),
            audit_record_id(identity.source().source_id(), identity.event_id())?,
            self.canonical_bytes().to_vec(),
        )?)
    }
    /// Compare an authenticated entry with the exact audit bytes and identity.
    pub fn matches_entry(&self, entry: &Entry) -> bool {
        self.append_request()
            .is_ok_and(|request| entry.matches(&request))
    }
}
