#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
mod borrowed;
mod control;
pub use borrowed::{append_in_transaction, lock_head_in_transaction, read_window_in_transaction};
mod error;
#[cfg(feature = "messaging")]
mod messaging;
#[cfg(feature = "messaging")]
pub use messaging::{append_in, lock_head_in, validate_in};
mod probe;
pub use probe::{validate_connection, validate_read_connection};
mod repository;
mod transaction;
pub use control::{Control, Timer};
pub use error::{AdmissionViolation, Error};
pub use repository::{ReadLimit, StagedAppend, Window};
#[cfg(feature = "integration")]
pub use transaction::PgFault;
pub use transaction::{Committed, LedgerTransaction, PgLedger};
/// Fresh V1 schema. Execute externally under a dedicated non-superuser, non-BYPASSRLS owner.
pub const MIGRATION_SQL: &str = concat!(
    include_str!("../migrations/0001_create_ledger.sql"),
    include_str!("../migrations/0002_return_locked_head.sql")
);
/// Upgrade existing Ledger functions without changing entries, keys or authentication bytes.
pub const LOCKED_HEAD_UPGRADE_SQL: &str = include_str!("../migrations/0002_return_locked_head.sql");
