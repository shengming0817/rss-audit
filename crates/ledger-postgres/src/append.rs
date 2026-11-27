//! One locked chain per logical batch. Physical statements bound both old and new payloads.
use crate::{Error, StagedAppend, error::sql_error, repository::{decode,encode_sequence}};
use futures::TryStreamExt;
use rss_ledger::{AppendRequest,Authenticator,ChainAppender,Entry,LedgerId,RecordId,Sequence};
use sqlx::{PgConnection,Row};
use std::collections::BTreeMap;

// A history hit can contain a full 1 MiB payload even when the proposed retry is tiny.
const ROWS_PER_STATEMENT: usize = 32;

pub(crate) async fn one(c: &mut PgConnection, auth: &Authenticator, request: &AppendRequest) -> Result<StagedAppend,Error> {
    batch(c, auth, std::slice::from_ref(request), |entry,inserted| StagedAppend {entry,inserted})
        .await?.pop().ok_or(Error::StorageContract)
}

pub(crate) async fn positions(c: &mut PgConnection, auth: &Authenticator, requests: &[AppendRequest]) -> Result<Vec<(Sequence,bool)>,Error> {
    batch(c, auth, requests, |entry,inserted| (entry.sequence(), inserted)).await
}

async fn batch<R>(
    c: &mut PgConnection, auth: &Authenticator, requests: &[AppendRequest], project: fn(Entry,bool)->R,
) -> Result<Vec<R>, Error> {
    let Some(first) = requests.first() else { return Ok(Vec::new()) };
    let ledger = first.ledger();
    if requests.iter().any(|r| r.ledger() != ledger) { return Err(rss_ledger::Error::ScopeMismatch.into()); }
    let mut signer = locked_signer(c,auth,ledger).await?;
    let mut result = Vec::with_capacity(requests.len());
    for chunk in requests.chunks(ROWS_PER_STATEMENT) {
        let mut known = history(c, auth, ledger, chunk, signer.sequence()).await?;
        let mut fresh = Vec::with_capacity(chunk.len());
        for request in chunk {
            if let Some(entry) = known.get(request.record_id()) {
                if !entry.matches(request) { return Err(Error::Conflict); }
                result.push(project(entry.clone(), false));
            } else {
                let entry = signer.append(request)?;
                encode_sequence(entry.sequence())?;
                known.insert(entry.record_id().clone(),entry.clone());
                fresh.push(entry.clone());
                result.push(project(entry,true));
            }
        }
        if !fresh.is_empty() { persist(c, auth, ledger, &fresh).await?; }
    }
    Ok(result)
}

async fn locked_signer<'a>(c: &mut PgConnection, auth: &'a Authenticator, ledger: &'a LedgerId) -> Result<ChainAppender<'a>,Error> {
    let head = sqlx::query("SELECT seq,tag FROM rss_ledger.prepare_append($1::uuid,$2,$3,1::smallint)")
        .bind(ledger.tenant().to_string()).bind(ledger.chain().as_str()).bind(auth.key_id().as_str())
        .fetch_one(&mut *c).await.map_err(sql_error)?;
    let Some(seq) = head.try_get::<Option<i64>,_>("seq").map_err(sql_error)? else {return Ok(auth.appender(ledger,None)?)};
    // A lock wait can outlive the snapshot that began the previous statement.
    let row = sqlx::query("SELECT *,tenant_id::text AS tenant_text FROM rss_ledger.entries WHERE tenant_id=$1::uuid AND chain_id=$2 AND seq=$3")
        .bind(ledger.tenant().to_string()).bind(ledger.chain().as_str()).bind(seq)
        .fetch_optional(c).await.map_err(sql_error)?.ok_or(Error::StorageContract)?;
    let entry = decode(row)?;
    let signer = auth.appender(ledger, Some(&entry))?;
    if head.try_get::<&[u8],_>("tag").map_err(sql_error)? != entry.tag().as_bytes() { return Err(Error::StorageContract); }
    Ok(signer)
}

async fn history(c: &mut PgConnection, auth: &Authenticator, ledger: &LedgerId, chunk: &[AppendRequest], tail: Option<Sequence>) -> Result<BTreeMap<RecordId,Entry>, Error> {
    let ids: Vec<_> = chunk.iter().map(|r|r.record_id().as_str()).collect();
    let mut rows = sqlx::query("SELECT *,tenant_id::text AS tenant_text FROM rss_ledger.entries WHERE tenant_id=$1::uuid AND chain_id=$2 AND record_id=ANY($3)")
        .bind(ledger.tenant().to_string()).bind(ledger.chain().as_str()).bind(ids).fetch(c);
    let mut known = BTreeMap::new();
    while let Some(row) = rows.try_next().await.map_err(sql_error)? {
        let entry = decode(row)?;
        auth.verify(&entry)?;
        if tail.is_none_or(|seq| entry.sequence() > seq) { return Err(Error::StorageContract); }
        known.insert(entry.record_id().clone(),entry);
    }
    Ok(known)
}

async fn persist(c: &mut PgConnection, auth: &Authenticator, ledger: &LedgerId, entries: &[Entry]) -> Result<(),Error> {
    let ids: Vec<_> = entries.iter().map(|e|e.record_id().as_str()).collect();
    let seqs = entries.iter().map(|e|encode_sequence(e.sequence())).collect::<Result<Vec<_>,_>>()?;
    let previous: Vec<_> = entries.iter().map(|e|*e.previous_tag().as_bytes()).collect();
    let tags: Vec<_> = entries.iter().map(|e|*e.tag().as_bytes()).collect();
    let payloads: Vec<_> = entries.iter().map(Entry::payload).collect();
    sqlx::query("SELECT rss_ledger.insert_entries($1::uuid,$2,$3,1::smallint,$4,$5,$6,$7,$8)")
        .bind(ledger.tenant().to_string()).bind(ledger.chain().as_str()).bind(auth.key_id().as_str())
        .bind(ids).bind(seqs).bind(previous.iter().map(|v|v.as_slice()).collect::<Vec<_>>())
        .bind(tags.iter().map(|v|v.as_slice()).collect::<Vec<_>>()).bind(payloads)
        .execute(c).await.map_err(sql_error)?;
    Ok(())
}
