use crate::{Cursor, Error, Page, ReadLimit, Record, StagedAppend, probe};
use rss_audit_core::{AuditEventV1, PreparedAuditV1, RecordIdentity, decode_untrusted};
use rss_request_context::TenantId;
use sqlx::{PgConnection, Row, postgres::PgRow};

pub(crate) async fn lock_head(c: &mut PgConnection, tenant: TenantId) -> Result<(), Error> {
    probe::tenant(c, tenant).await?;
    sqlx::query("SELECT rss_audit.reserve($1::uuid)")
        .bind(tenant.to_string())
        .execute(c)
        .await?;
    Ok(())
}

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

pub(crate) async fn find(
    c: &mut PgConnection,
    identity: &RecordIdentity,
) -> Result<Option<Record>, Error> {
    probe::tenant(c, identity.tenant()).await?;
    let row = sqlx::query("SELECT tenant_id::text,source_id,event_id,position,recorded_at,canonical,ledger_sequence FROM rss_audit.records WHERE tenant_id=$1::uuid AND source_id=$2 AND event_id=$3")
        .bind(identity.tenant().to_string()).bind(identity.source().source_id().as_str()).bind(identity.event_id().as_str())
        .fetch_optional(c).await?;
    row.as_ref()
        .map(|r| decode(r, identity.tenant()))
        .transpose()
}

pub(crate) async fn reserve(
    c: &mut PgConnection,
    request: &PreparedAuditV1,
    ledger: bool,
) -> Result<Option<Record>, Error> {
    let decoded = decode_untrusted(request.canonical_bytes())?;
    let identity = decoded.event().identity();
    lock_head(c, identity.tenant()).await?;
    let existing = find(c, identity).await?;
    if let Some(record) = &existing
        && (record.prepared.canonical_bytes() != request.canonical_bytes()
            || record.ledger_sequence.is_some() != ledger)
    {
        return Err(Error::Conflict);
    }
    Ok(existing)
}

pub(crate) async fn finish(
    c: &mut PgConnection,
    request: &PreparedAuditV1,
    existing: Option<Record>,
    ledger: Option<(u64, bool)>,
) -> Result<StagedAppend, Error> {
    let sequence = ledger.map(|(seq, _)| seq);
    if let Some(record) = existing {
        if record.ledger_sequence != sequence || ledger.is_some_and(|(_, inserted)| inserted) {
            return Err(Error::StorageContract);
        }
        return Ok(StagedAppend {
            record,
            inserted: false,
        });
    }
    if ledger.is_some_and(|(_, inserted)| !inserted) {
        return Err(Error::StorageContract);
    }
    let decoded = decode_untrusted(request.canonical_bytes())?;
    let identity = decoded.event().identity();
    let position: i64 = sqlx::query_scalar("SELECT rss_audit.append($1::uuid,$2,$3,$4,$5,$6)")
        .bind(identity.tenant().to_string())
        .bind(identity.source().source_id().as_str())
        .bind(identity.event_id().as_str())
        .bind(decoded.recorded_at().unix_seconds())
        .bind(request.canonical_bytes())
        .bind(
            sequence
                .map(i64::try_from)
                .transpose()
                .map_err(|_| Error::StorageContract)?,
        )
        .fetch_one(c)
        .await?;
    if position < 0 {
        return Err(Error::StorageContract);
    }
    Ok(StagedAppend {
        record: Record {
            position,
            prepared: request.clone(),
            ledger_sequence: sequence,
        },
        inserted: true,
    })
}

fn decode(row: &PgRow, tenant: TenantId) -> Result<Record, Error> {
    let bytes: Vec<u8> = row.try_get("canonical")?;
    let prepared =
        PreparedAuditV1::from_canonical_bytes(&bytes).map_err(|_| Error::StorageContract)?;
    let decoded = decode_untrusted(&bytes).map_err(|_| Error::StorageContract)?;
    let identity = decoded.event().identity();
    let position: i64 = row.try_get("position")?;
    if identity.tenant() != tenant
        || row.try_get::<String, _>("tenant_id")? != tenant.to_string()
        || row.try_get::<&str, _>("source_id")? != identity.source().source_id().as_str()
        || row.try_get::<&str, _>("event_id")? != identity.event_id().as_str()
        || row.try_get::<i64, _>("recorded_at")? != decoded.recorded_at().unix_seconds()
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
        .filter(|r| r.position < through)
        .map(|r| Cursor::resume(cursor.tenant(), r.position(), through as u64))
        .transpose()?;
    Ok(Page { records, next })
}
