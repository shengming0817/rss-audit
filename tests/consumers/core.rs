use rss_audit_core::{
    Action, ActorId, ActorKind, ActorRef, AuditEventV1, AuditPayload, Coordinates, EventContext,
    EventFacts, EventId, Outcome, RecordIdentity, ResourceId, ResourceKind, ResourceRef,
    SourceContract, SourceId, SourceIdentity, decode_untrusted, prepare, verify_window,
};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_ledger::{Authenticator, KeyId};
use rss_request_context::TenantId;

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
            ActorRef::new(ActorKind::parse("service")?, ActorId::parse("consumer")?),
            Action::parse("read")?,
            ResourceRef::new(
                ResourceKind::parse("document")?,
                ResourceId::parse("document-1")?,
            ),
            Outcome::Succeeded,
            Timepoint::try_from(1_i64)?,
        ),
        EventContext::new(
            Coordinates::new(None, None, None),
            AuditPayload::new(b"bounded".to_vec())?,
        ),
    );
    let prepared = prepare(event, Timepoint::try_from(2_i64)?)?;
    let decoded = decode_untrusted(prepared.canonical_bytes())?;
    assert_eq!(
        prepared.append_request().record_id().as_str(),
        "v1:consumer:event-1"
    );
    assert_eq!(decoded.recorded_at().unix_seconds(), 2);
    assert_eq!(decoded.event().context().payload().as_bytes(), b"bounded");
    let authenticator = Authenticator::new(KeyId::parse("consumer-key-v1")?, vec![0x5a; 32])?;
    let entry = authenticator.append(prepared.append_request(), None)?;
    assert!(prepared.matches_entry(&entry));
    let verified = verify_window(&authenticator, tenant, None, std::slice::from_ref(&entry))?;
    assert_eq!(verified.ledger_verification().count(), 1);
    assert_eq!(verified.records()[0].record().event().identity().tenant(), tenant);
    Ok(())
}
