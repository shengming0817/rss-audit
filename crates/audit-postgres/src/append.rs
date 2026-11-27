//! The first occurrence determines signing order. PostgreSQL orders Audit's unique-key locks.
use crate::{Error, Record, StagedAppend};
use rss_audit_core::PreparedAuditV1;
use std::collections::BTreeMap;

type Key<'a> = (&'a str, &'a str);

pub(crate) struct Batch<'a> {
    pub(crate) unique: Vec<&'a PreparedAuditV1>,
    slots: BTreeMap<Key<'a>, usize>,
    order: Vec<usize>,
}

impl<'a> Batch<'a> {
    pub(crate) fn new(records: &'a [PreparedAuditV1]) -> Result<Self, Error> {
        let mut batch = Self { unique: Vec::new(), slots: BTreeMap::new(), order: Vec::with_capacity(records.len()) };
        for record in records {
            let id = record.identity();
            let key = (id.source().source_id().as_str(), id.event_id().as_str());
            let slot = match batch.slots.entry(key) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    let slot = batch.unique.len();
                    entry.insert(slot);
                    batch.unique.push(record);
                    slot
                }
                std::collections::btree_map::Entry::Occupied(entry) => {
                    let slot = *entry.get();
                    if batch.unique[slot].canonical_bytes() != record.canonical_bytes() {
                        return Err(Error::Conflict);
                    }
                    slot
                }
            };
            batch.order.push(slot);
        }
        Ok(batch)
    }

    pub(crate) fn slot(&self, source: &str, event: &str) -> Result<usize, Error> {
        self.slots.get(&(source, event)).copied().ok_or(Error::StorageContract)
    }

    #[cfg(feature = "ledger")]
    pub(crate) fn ledger_requests(&self) -> Result<Vec<rss_ledger::AppendRequest>, Error> {
        self.unique.iter().map(|record| Ok(record.append_request()?)).collect()
    }

    pub(crate) fn receipts(self, mut stored: Vec<Option<(Record, bool)>>) -> Result<Vec<StagedAppend>, Error> {
        self.order.into_iter().map(|slot| {
            let (record, inserted) = stored[slot].as_mut().ok_or(Error::StorageContract)?;
            Ok(StagedAppend { record: record.clone(), inserted: std::mem::take(inserted) })
        }).collect()
    }
}
