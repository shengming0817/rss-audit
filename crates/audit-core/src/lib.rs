#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod codec;
mod error;
mod identity;
mod ledger;
mod model;

pub use codec::{MAX_PAYLOAD_BYTES, MAX_RECORD_BYTES, decode_untrusted};
pub use error::{Error, Field};
pub use identity::{
    Action, ActorId, ActorKind, ActorRef, AuditPayload, EventId, OperationId, ResourceId,
    ResourceKind, ResourceRef, SourceContract, SourceId, SourceIdentity,
};
pub use ledger::{
    AUDIT_CHAIN_ID, PreparedAuditV1, VerifiedAuditEntryV1, VerifiedAuditWindow, prepare,
    verify_window,
};
pub use model::{
    AuditEventV1, Coordinates, DecodedAuditV1, EventContext, EventFacts, Outcome, RecordIdentity,
    RecordVersion,
};
