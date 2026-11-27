use rss_audit_core::{Outcome, PreparedAuditV1};
use rss_audit_postgres::{Error, Page};
use rss_request_context::TenantId;
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PageDto {
    tenant_id: String,
    integrity: &'static str,
    entries: Vec<EntryDto>,
    next_cursor: Option<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct EntryDto {
    position: String,
    source_id: String,
    event_id: String,
    action: String,
    outcome: &'static str,
    occurred_at: String,
    recorded_at: String,
    ledger: Option<LedgerDto>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LedgerDto {
    chain_id: String,
    record_id: String,
    sequence: String,
}
/// All fallible page checks are complete when this value leaves the transaction.
pub(crate) struct CheckedPage {
    tenant: TenantId,
    page: Page,
    continuation: Option<(u64, u64)>,
}
impl CheckedPage {
    pub(crate) fn new(tenant: TenantId, page: Page) -> Result<Self, Error> {
        let continuation = page
            .next()
            .map(|cursor| cursor.continuation().ok_or(Error::StorageContract))
            .transpose()?;
        Ok(Self {
            tenant,
            page,
            continuation,
        })
    }
    pub(crate) fn into_dto(self) -> PageDto {
        PageDto {
            tenant_id: self.tenant.to_string(),
            integrity: "unverified",
            entries: self
                .page
                .records()
                .iter()
                .map(|record| {
                    entry(
                        record.prepared(),
                        record.position(),
                        record.ledger_sequence(),
                    )
                })
                .collect(),
            next_cursor: self
                .continuation
                .map(|(after, through)| crate::query::encode(self.tenant, after, through)),
        }
    }
}
fn entry(prepared: &PreparedAuditV1, position: u64, sequence: Option<u64>) -> EntryDto {
    let id = prepared.identity();
    EntryDto {
        position: position.to_string(),
        source_id: id.source().source_id().as_str().to_owned(),
        event_id: id.event_id().as_str().to_owned(),
        action: prepared.action().as_str().to_owned(),
        outcome: outcome(prepared.outcome()),
        occurred_at: prepared.occurred_at().unix_seconds().to_string(),
        recorded_at: prepared.recorded_at().unix_seconds().to_string(),
        ledger: sequence.map(|sequence| LedgerDto {
            chain_id: "rss.audit.v1".to_owned(),
            record_id: format!(
                "v1:{}:{}",
                id.source().source_id().as_str(),
                id.event_id().as_str()
            ),
            sequence: sequence.to_string(),
        }),
    }
}

fn outcome(value: Outcome) -> &'static str {
    match value {
        Outcome::Succeeded => "succeeded",
        Outcome::Denied => "denied",
        Outcome::Failed => "failed",
        Outcome::Unknown => "unknown",
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn summary_allocations_are_independent_of_payload_size() -> anyhow::Result<()> {
        use rss_audit_core::*;
        use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
        use std::hint::black_box;
        let at = Timepoint::try_from(42_i64)?;
        let tenant = TenantId::parse("018f47c2-8bd8-7f21-a52b-8d4f6ee2b203")?;
        let make = |size| -> anyhow::Result<_> {
            Ok(prepare(
                AuditEventV1::new(
                    RecordIdentity::new(
                        tenant,
                        SourceIdentity::new(
                            SourceId::parse("test")?,
                            SourceContract::new(
                                ContractId::from_static("test.audit"),
                                ContractVersion::from_major(1)?,
                                SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64)))?,
                            ),
                        ),
                        EventId::parse("event")?,
                    ),
                    EventFacts::new(
                        ActorRef::new(ActorKind::parse("user")?, ActorId::parse("actor")?),
                        Action::parse("read")?,
                        ResourceRef::new(ResourceKind::parse("doc")?, ResourceId::parse("ref")?),
                        Outcome::Succeeded,
                        at,
                    ),
                    EventContext::new(
                        Coordinates::new(None, None, None),
                        AuditPayload::new(vec![7; size])?,
                    ),
                ),
                at,
            )?)
        };
        let empty = make(0)?;
        let small = make(32)?;
        let big = make(MAX_RECORD_BYTES - empty.canonical_bytes().len())?;
        let project = |rows: [&PreparedAuditV1; 8]| {
            allocation_counter::measure(|| {
                black_box(rows.map(|row| entry(row, 1, Some(1))));
            })
        };
        let reference = project([&empty; 8]);
        for rows in [
            [&small; 8],
            [&big; 8],
            [&small, &big, &small, &big, &small, &big, &small, &big],
        ] {
            let measured = project(rows);
            assert_eq!(
                (measured.count_total, measured.bytes_total),
                (reference.count_total, reference.bytes_total)
            );
        }
        // A full owned decode materializes the payload. The same allocator observes the copy.
        let positive = allocation_counter::measure(|| {
            black_box(decode_untrusted(big.canonical_bytes()).ok());
        });
        assert!(positive.bytes_total >= (MAX_RECORD_BYTES - empty.canonical_bytes().len()) as u64);
        Ok(())
    }
    #[test]
    fn outcome_wire_labels_preserve_unknown() {
        for (value, expected) in [
            (Outcome::Succeeded, "succeeded"),
            (Outcome::Denied, "denied"),
            (Outcome::Failed, "failed"),
            (Outcome::Unknown, "unknown"),
        ] {
            assert_eq!(outcome(value), expected);
        }
    }
}
