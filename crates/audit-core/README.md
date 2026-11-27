# rss-audit-core

Provider-free Audit V1 record values, canonical encoding; the optional `ledger` feature adds chain mapping and authentication.

This crate does not authenticate sources, persist records or produce commit evidence.

The example below constructs and decodes a record. The crate's protocol and ledger composition
tests cover canonical bytes, replay identity and authenticated Audit windows.

```rust
use rss_audit_core::{
    Action, ActorId, ActorKind, ActorRef, AuditEventV1, AuditPayload, Coordinates,
    EventContext, EventFacts, EventId, Outcome, RecordIdentity, ResourceId, ResourceKind,
    ResourceRef, SourceContract, SourceId, SourceIdentity, decode_untrusted, prepare,
};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_request_context::TenantId;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let tenant = TenantId::parse("018f47c2-8bd8-7f21-a52b-8d4f6ee2b203")?;
let event = AuditEventV1::new(
    RecordIdentity::new(
        tenant,
        SourceIdentity::new(
            SourceId::parse("consumer")?,
            SourceContract::new(
                ContractId::parse("consumer.audit-event")?,
                ContractVersion::from_major(1)?,
                SchemaDigest::parse(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                )?,
            ),
        ),
        EventId::parse("event-1")?,
    ),
    EventFacts::new(
        ActorRef::new(ActorKind::parse("service")?, ActorId::parse("service-1")?),
        Action::parse("read")?,
        ResourceRef::new(
            ResourceKind::parse("document")?,
            ResourceId::parse("document-1")?,
        ),
        Outcome::Succeeded,
        Timepoint::try_from(1_i64)?,
    ),
    EventContext::new(Coordinates::new(None, None, None), AuditPayload::new(Vec::new())?),
);
let prepared = prepare(event, Timepoint::try_from(2_i64)?)?;
let decoded = decode_untrusted(prepared.canonical_bytes())?;
assert_eq!(decoded.event().facts().action().as_str(), "read");
# Ok(())
# }
```

`PreparedAuditV1` shares immutable exact bytes and validated identity, action, outcome and occurrence/recording times without Ledger types.
The default build does not depend on Ledger. Enable `ledger` for `append_request`, authenticated
windows and Ledger errors. Mapping is fallible and returns an owned request; it never persists data.
The two Ledger crates live in this workspace and are not independently published. Public RSS
contract and tenant types still use this repository's single pinned RSS commit.

Source/event IDs, actor/resource kinds, actions and operation IDs accept up to 255 bytes with
their existing token grammars. Actor/resource references accept up to 512 UTF-8 bytes.
Payload has no separate 64 KiB limit: the complete canonical record, including identities,
headers and length prefixes, must fit within `MAX_RECORD_BYTES` (128 KiB). `AuditPayload::new`
only performs a bounded preliminary check; successful construction is not record admission.
Correlation IDs follow the pinned RSS owner (255 bytes); request IDs retain their own 128-byte bound.

Use `decode_untrusted` for structural decoding and optional `verify_window` for an exact
Ledger range. Neither proves source truth, completeness or durable commit.

`Outcome::Unknown` (V1 tag 4) records an unconfirmed source-operation outcome; it is not
`Failed` or rollback evidence. Sources keep business events and per-request settlement
identities separate, so resolving a request cannot overwrite a prior business event.
