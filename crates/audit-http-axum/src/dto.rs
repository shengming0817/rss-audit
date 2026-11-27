use rss_audit_core::Outcome;
use rss_audit_postgres::{Error, Page, Record};
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
            entries: self.page.records().iter().map(entry).collect(),
            next_cursor: self
                .continuation
                .map(|(after, through)| crate::query::encode(self.tenant, after, through)),
        }
    }
}
fn entry(record: &Record) -> EntryDto {
    let prepared = record.prepared();
    let id = prepared.identity();
    EntryDto {
        position: record.position().to_string(),
        source_id: id.source().source_id().as_str().to_owned(),
        event_id: id.event_id().as_str().to_owned(),
        action: prepared.action().as_str().to_owned(),
        outcome: outcome(prepared.outcome()),
        occurred_at: prepared.occurred_at().unix_seconds().to_string(),
        recorded_at: prepared.recorded_at().unix_seconds().to_string(),
        ledger: record.ledger_sequence().map(|sequence| LedgerDto {
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
