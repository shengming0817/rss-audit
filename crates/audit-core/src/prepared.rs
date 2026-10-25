use crate::{AuditEventV1, Error, RecordIdentity, codec};
use rss_contract::Timepoint;

/// Provider-free exact Audit bytes and identity; never durable commit evidence.
#[derive(Clone)]
pub struct PreparedAuditV1 {
    identity: RecordIdentity,
    recorded_at: Timepoint,
    canonical: Vec<u8>,
}
impl PreparedAuditV1 {
    /// Restore structurally valid canonical bytes without authenticating their source or time.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (event, recorded_at) = codec::decode_untrusted(bytes)?.into_parts();
        let prepared = prepare(event, recorded_at)?;
        if prepared.canonical_bytes() != bytes {
            return Err(Error::MalformedEncoding);
        }
        Ok(prepared)
    }
    /// Stable tenant, source and event identity.
    pub const fn identity(&self) -> &RecordIdentity {
        &self.identity
    }
    /// Recording time supplied by the recorder authority.
    pub const fn recorded_at(&self) -> Timepoint {
        self.recorded_at
    }
    /// Exact retry bytes, including the original recording time.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}
impl std::fmt::Debug for PreparedAuditV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedAuditV1([redacted])")
    }
}
/// Encode an audit record. The caller owns the recording-time authority.
pub fn prepare(event: AuditEventV1, recorded_at: Timepoint) -> Result<PreparedAuditV1, Error> {
    let canonical = codec::encode(&event, recorded_at)?;
    Ok(PreparedAuditV1 {
        identity: event.identity().clone(),
        recorded_at,
        canonical,
    })
}
