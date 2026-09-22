# rss-audit-core

Provider-free Audit V1 record values, canonical encoding and `rss-ledger` composition.

This crate does not authenticate sources, persist records or produce commit evidence.

The complete standalone consumer is [`tests/consumers/core.rs`](../../tests/consumers/core.rs).
It constructs and decodes a record, appends it through `rss-ledger`, checks exact replay identity,
and authenticates the resulting Audit window. The repository verification gate runs that path both
from source and from a fixed Git revision.

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

The embedding manifest pins `rss-audit-core` to an accepted full Git commit. Because the public
API uses the canonical RSS owners for tenant, contract, time and ledger values, the consumer
declares `rss-contract`, `rss-ledger` and `rss-request-context` at the exact RSS revision recorded in
this repository's `Cargo.toml`; the consumer check enforces one source.

Use `decode_untrusted` only for structural decoding and `verify_window` when authenticating an
exact ledger range. Both return the closed [`Error`](crate::Error) categories without
including rejected values; callers retain ownership of retry policy, diagnostics and commit proof.
