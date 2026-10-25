#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod borrowed;
mod control;
mod error;
#[cfg(feature = "messaging")]
mod messaging;
#[cfg(feature = "messaging")]
pub use messaging::{append_batch_in, append_in, lock_head_in, validate_in};
mod model;
mod probe;
mod reader;
mod repository;
mod runtime;
pub use reader::PgAuditReader;
mod transaction;

pub use control::Control;
pub use error::{AdmissionViolation, Error, StorageFailure, TransactionError};
pub use model::{Cursor, Page, ReadLimit, Record, StagedAppend};
#[cfg(feature = "integration")]
pub use runtime::PgFault;
pub use runtime::{Committed, Integrity, PgAudit};
pub use transaction::{ReadAuditTransaction, WriteAuditTransaction};

/// Fresh PostgreSQL schema; execute only through the separately provisioned migration owner.
pub const MIGRATION_SQL: &str = concat!(
    include_str!("../migrations/0001_audit.sql"),
    include_str!("../migrations/0002_batch_navigation.sql")
);
/// One-way upgrade with writers stopped; preserves records and optional Ledger history.
pub const NAVIGATION_UPGRADE_SQL: &str = include_str!("../migrations/0002_batch_navigation.sql");
