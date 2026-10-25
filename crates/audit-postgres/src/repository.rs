use crate::{Cursor, Error, Page, ReadLimit, Record, StagedAppend, probe};
use rss_audit_core::{AuditEventV1, PreparedAuditV1};
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row, postgres::PgRow};

pub(crate) async fn prepare(
    c: &mut PgConnection,
    event: AuditEventV1,
) -> Result<PreparedAuditV1, Error> {
    let seconds: i64 =
        sqlx::query_scalar("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint")
            .fetch_one(c)
            .await?;
    let recorded =
        rss_contract::Timepoint::try_from(seconds).map_err(|_| Error::StorageContract)?;
    Ok(rss_audit_core::prepare(event, recorded)?)
}

/// One tenant and exact identities per batch, before any persistence is attempted.
pub(crate) fn batch_tenant(requests: &[PreparedAuditV1]) -> Result<TenantId, Error> {
    let tenant = requests
        .first()
        .ok_or(Error::InvalidBound)?
        .identity()
        .tenant();
    if requests.iter().any(|r| r.identity().tenant() != tenant) {
        return Err(Error::ScopeMismatch);
    }
    Ok(tenant)
}

/// Shared physical Audit write. The enclosing owner must roll back on any error.
pub(crate) async fn append_batch(
    c: &mut PgConnection,
    requests: &[PreparedAuditV1],
    ledger: &[Option<(u64, bool)>],
) -> Result<Vec<StagedAppend>, Error> {
    use std::collections::{BTreeMap, BTreeSet};
    if requests.is_empty() {
        return Ok(Vec::new());
    }
    let tenant = batch_tenant(requests)?;
    if ledger.len() != requests.len() {
        return Err(Error::StorageContract);
    }
    let key = |r: &PreparedAuditV1| {
        (
            r.identity().source().source_id().as_str().to_owned(),
            r.identity().event_id().as_str().to_owned(),
        )
    };
    let mut unique = BTreeMap::new();
    for (i, request) in requests.iter().enumerate() {
        if let Some(previous) = unique.insert(key(request), i) {
            if requests[previous].canonical_bytes() != request.canonical_bytes() {
                return Err(Error::Conflict);
            }
            // Preserve the first insertion flag when one input repeats its identity.
            unique.insert(key(request), previous);
        }
    }
    let mut sources = Vec::with_capacity(unique.len());
    let mut events = Vec::with_capacity(unique.len());
    let mut recorded = Vec::with_capacity(unique.len());
    let mut canonical = Vec::with_capacity(unique.len());
    let mut sequences = Vec::with_capacity(unique.len());
    for ((source, event), &i) in &unique {
        sources.push(source.as_str());
        events.push(event.as_str());
        recorded.push(requests[i].recorded_at().unix_seconds());
        canonical.push(requests[i].canonical_bytes());
        sequences.push(
            ledger[i]
                .map(|(seq, _)| i64::try_from(seq))
                .transpose()
                .map_err(|_| Error::StorageContract)?,
        );
    }
    let inserted: Vec<(String, String)> = sqlx::query_as(
        "SELECT source_id,event_id FROM rss_audit.append_batch($1::uuid,$2,$3,$4,$5,$6)",
    )
    .bind(tenant.to_string())
    .bind(&sources)
    .bind(&events)
    .bind(recorded)
    .bind(canonical)
    .bind(sequences)
    .fetch_all(&mut *c)
    .await?;
    let mut inserted: BTreeSet<_> = inserted.into_iter().collect();
    // A new READ COMMITTED snapshot sees competing inserts waited for by ON CONFLICT.
    // Stronger isolation may instead report serialization failure; only the host retries.
    let rows = sqlx::query("SELECT r.tenant_id::text,r.source_id,r.event_id,r.position,r.recorded_at,r.canonical,r.ledger_sequence FROM rss_audit.records r JOIN unnest($2::text[],$3::text[]) AS i(source_id,event_id) ON r.source_id=i.source_id AND r.event_id=i.event_id WHERE r.tenant_id=$1::uuid")
        .bind(tenant.to_string()).bind(sources).bind(events).fetch_all(c).await?;
    let mut records = BTreeMap::new();
    for row in rows {
        let record = decode(&row, tenant)?;
        records.insert(key(record.prepared()), record);
    }
    let mut result = Vec::with_capacity(requests.len());
    for (request, expected) in requests.iter().zip(ledger) {
        let id = key(request);
        let record = records.get(&id).ok_or(Error::StorageContract)?;
        check_existing(request, Some(record), expected.is_some())?;
        let added = inserted.remove(&id);
        if record.ledger_sequence != expected.map(|(seq, _)| seq)
            || expected.is_some_and(|(_, was_inserted)| was_inserted != added)
        {
            return Err(Error::StorageContract);
        }
        result.push(StagedAppend {
            record: record.clone(),
            inserted: added,
        });
    }
    Ok(result)
}

fn decode(row: &PgRow, tenant: TenantId) -> Result<Record, Error> {
    let bytes: Vec<u8> = row.try_get("canonical")?;
    let prepared =
        PreparedAuditV1::from_canonical_bytes(&bytes).map_err(|_| Error::StorageContract)?;
    let identity = prepared.identity();
    let position: i64 = row.try_get("position")?;
    if identity.tenant() != tenant
        || row.try_get::<String, _>("tenant_id")? != tenant.to_string()
        || row.try_get::<&str, _>("source_id")? != identity.source().source_id().as_str()
        || row.try_get::<&str, _>("event_id")? != identity.event_id().as_str()
        || row.try_get::<i64, _>("recorded_at")? != prepared.recorded_at().unix_seconds()
        || position < 0
    {
        return Err(Error::StorageContract);
    }
    let ledger_sequence = row
        .try_get::<Option<i64>, _>("ledger_sequence")?
        .map(u64::try_from)
        .transpose()
        .map_err(|_| Error::StorageContract)?;
    Ok(Record {
        position,
        prepared,
        ledger_sequence,
    })
}

pub(crate) async fn page(
    c: &mut PgConnection,
    cursor: Cursor,
    limit: ReadLimit,
) -> Result<Page, Error> {
    probe::tenant(c, cursor.tenant()).await?;
    // Metadata first, in the very same statement snapshot as the payload. An over-budget
    // candidate never sends canonical bytes to SQLx, even when a single row is too large.
    let rows = sqlx::query(include_str!("page.sql"))
        .bind(cursor.tenant().to_string())
        .bind(cursor.after)
        .bind(limit.rows)
        .bind(limit.bytes)
        .bind(cursor.through)
        .fetch_all(c)
        .await?;
    let mut through = -1;
    let mut has_more = false;
    let mut records = Vec::new();
    let mut bytes = 0_i64;
    for row in rows {
        match row.try_get::<i32, _>("status")? {
            0 => {}
            1 => return Err(Error::ReadBudgetExceeded),
            3 => return Err(Error::InvalidBound),
            _ => return Err(Error::StorageContract),
        }
        through = row.try_get("through")?;
        has_more = row.try_get("has_more")?;
        if row.try_get::<Option<i64>, _>("position")?.is_none() {
            continue;
        }
        let record = decode(&row, cursor.tenant())?;
        bytes = bytes
            .checked_add(
                i64::try_from(record.prepared.canonical_bytes().len())
                    .map_err(|_| Error::StorageContract)?,
            )
            .ok_or(Error::StorageContract)?;
        if bytes > limit.bytes || records.len() >= limit.rows as usize {
            return Err(Error::StorageContract);
        }
        records.push(record);
    }
    let next = records
        .last()
        .filter(|_| has_more)
        .map(|r| Cursor::resume(cursor.tenant(), r.position(), through as u64))
        .transpose()?;
    Ok(Page { records, next })
}

fn check_existing(
    request: &PreparedAuditV1,
    existing: Option<&Record>,
    ledger: bool,
) -> Result<(), Error> {
    if let Some(record) = existing
        && (record.prepared.canonical_bytes() != request.canonical_bytes()
            || record.ledger_sequence.is_some() != ledger)
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
