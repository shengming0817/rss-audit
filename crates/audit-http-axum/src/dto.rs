use rss_audit_core::{Outcome, decode_untrusted};
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
impl PageDto {
    pub(crate) fn new(tenant: TenantId, page: &Page) -> Result<Self, Error> {
        Ok(Self {
            tenant_id: tenant.to_string(),
            integrity: "unverified",
            entries: page.records().iter().map(entry).collect::<Result<_, _>>()?,
            next_cursor: page.next().map(crate::query::encode).transpose()?,
        })
    }
}
fn entry(record: &Record) -> Result<EntryDto, Error> {
    let decoded = decode_untrusted(record.prepared().canonical_bytes())
        .map_err(|_| Error::StorageContract)?;
    let event = decoded.event();
    let facts = event.facts();
    let request = record.prepared().append_request();
    Ok(EntryDto {
        position: record.position().to_string(),
        source_id: event.identity().source().source_id().as_str().to_owned(),
        event_id: event.identity().event_id().as_str().to_owned(),
        action: facts.action().as_str().to_owned(),
        outcome: match facts.outcome() {
            Outcome::Succeeded => "succeeded",
            Outcome::Denied => "denied",
            Outcome::Failed => "failed",
        },
        occurred_at: facts.occurred_at().unix_seconds().to_string(),
        recorded_at: decoded.recorded_at().unix_seconds().to_string(),
        ledger: record.ledger_sequence().map(|sequence| LedgerDto {
            chain_id: request.ledger().chain().as_str().to_owned(),
            record_id: request.record_id().as_str().to_owned(),
            sequence: sequence.to_string(),
        }),
    })
}
