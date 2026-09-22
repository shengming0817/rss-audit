use crate::Error;
use rss_audit_core::PreparedAuditV1;
use rss_request_context::TenantId;

/// Tenant-bound ordinary keyset cursor. It is not a ledger coordinate or checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    tenant: TenantId,
    pub(crate) after: i64,
}
impl Cursor {
    /// Start before the first persisted record.
    pub const fn start(tenant: TenantId) -> Self {
        Self { tenant, after: -1 }
    }
    /// Resume strictly after an already observed position.
    pub fn after(tenant: TenantId, position: u64) -> Result<Self, Error> {
        Ok(Self {
            tenant,
            after: i64::try_from(position).map_err(|_| Error::InvalidBound)?,
        })
    }
    /// Tenant bound into this cursor.
    pub const fn tenant(self) -> TenantId {
        self.tenant
    }
}

/// Explicit complete-page row and canonical-byte bounds.
#[derive(Clone, Copy, Debug)]
pub struct ReadLimit {
    pub(crate) rows: i64,
    pub(crate) bytes: i64,
}
impl ReadLimit {
    /// Select 1..=1024 rows and a positive PostgreSQL-representable byte budget.
    pub fn new(rows: u32, bytes: u64) -> Result<Self, Error> {
        if !(1..=1024).contains(&rows) || bytes == 0 {
            return Err(Error::InvalidBound);
        }
        Ok(Self {
            rows: i64::from(rows),
            bytes: i64::try_from(bytes).map_err(|_| Error::InvalidBound)?,
        })
    }
}

/// Structurally validated stored bytes, not authenticated ledger evidence.
#[derive(Clone, Debug)]
pub struct Record {
    pub(crate) position: i64,
    pub(crate) prepared: PreparedAuditV1,
    pub(crate) ledger_sequence: Option<u64>,
}
impl Record {
    /// Monotonic tenant-local pagination position, independent of the ledger sequence.
    pub fn position(&self) -> u64 {
        self.position as u64
    }
    /// Exact persisted canonical request, suitable for unchanged retry.
    pub const fn prepared(&self) -> &PreparedAuditV1 {
        &self.prepared
    }
    /// Actual persisted integrity coordinate. Presence alone does not authenticate the row.
    pub const fn ledger_sequence(&self) -> Option<u64> {
        self.ledger_sequence
    }
}

/// An append staged in the enclosing transaction; never commit evidence.
#[derive(Debug)]
pub struct StagedAppend {
    pub(crate) record: Record,
    pub(crate) inserted: bool,
}
impl StagedAppend {
    /// Persisted or staged record associated with the stable identity.
    pub const fn record(&self) -> &Record {
        &self.record
    }
    /// Whether this transaction inserted rather than replayed an existing record.
    pub const fn inserted(&self) -> bool {
        self.inserted
    }
}

/// Complete bounded ordinary page. Appends between pages may be visible on the next page.
#[derive(Debug)]
pub struct Page {
    pub(crate) records: Vec<Record>,
    pub(crate) next: Option<Cursor>,
}
impl Page {
    /// Structurally checked records; no cryptographic integrity claim.
    pub fn records(&self) -> &[Record] {
        &self.records
    }
    /// Resume after the last returned row, or no advance for an empty page.
    pub const fn next(&self) -> Option<Cursor> {
        self.next
    }
}
