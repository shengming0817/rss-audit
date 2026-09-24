#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod control;
mod error;
#[cfg(feature = "messaging")]
mod messaging;
mod model;
mod probe;
mod repository;
mod runtime;
mod transaction;

pub use control::Control;
pub use error::{AdmissionViolation, Error, StorageFailure, TransactionError};
pub use model::{Cursor, Page, ReadLimit, Record, StagedAppend};
#[cfg(feature = "integration")]
pub use runtime::PgFault;
pub use runtime::{Committed, Integrity, PgAudit};
pub use transaction::AuditTransaction;

/// Fresh PostgreSQL schema; execute only through the separately provisioned migration owner.
pub const MIGRATION_SQL: &str = include_str!("../migrations/0001_audit.sql");
