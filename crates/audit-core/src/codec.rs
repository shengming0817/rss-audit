use crate::{
    Action, ActorId, ActorKind, ActorRef, AuditEventV1, AuditPayload, Coordinates, DecodedAuditV1,
    Error, EventContext, EventFacts, EventId, Field, OperationId, Outcome, RecordIdentity,
    RecordVersion, ResourceId, ResourceKind, ResourceRef, SourceContract, SourceId, SourceIdentity,
};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_diag_context::CorrelationId;
use rss_request_context::{RequestId, TenantId};

const DOMAIN: &[u8] = b"rss.audit.record\0";
/// Maximum exact source payload bytes in Audit V1.
pub const MAX_PAYLOAD_BYTES: usize = 65_536;
/// Maximum complete canonical Audit V1 bytes.
pub const MAX_RECORD_BYTES: usize = 131_072;

pub(crate) fn encode(event: &AuditEventV1, recorded_at: Timepoint) -> Result<Vec<u8>, Error> {
    let identity = event.identity();
    let source = identity.source();
    let contract = source.contract();
    let facts = event.facts();
    let coordinates = event.context().coordinates();
    let mut bytes = Vec::with_capacity(event.context().payload().as_bytes().len() + 512);
    bytes.extend_from_slice(DOMAIN);
    bytes.extend_from_slice(&RecordVersion::V1.tag().to_be_bytes());
    bytes.extend_from_slice(&identity.tenant().octets());
    push_text(&mut bytes, source.source_id().as_str())?;
    push_text(&mut bytes, identity.event_id().as_str())?;
    push_text(&mut bytes, contract.id().as_str())?;
    bytes.extend_from_slice(&contract.version().major().to_be_bytes());
    push_text(&mut bytes, contract.schema_digest().as_str())?;
    push_text(&mut bytes, facts.actor().kind().as_str())?;
    push_text(&mut bytes, facts.actor().id().as_str())?;
    push_text(&mut bytes, facts.action().as_str())?;
    push_text(&mut bytes, facts.resource().kind().as_str())?;
    push_text(&mut bytes, facts.resource().id().as_str())?;
    bytes.push(facts.outcome().tag());
    bytes.extend_from_slice(&facts.occurred_at().unix_seconds().to_be_bytes());
    bytes.extend_from_slice(&recorded_at.unix_seconds().to_be_bytes());
    push_optional(
        &mut bytes,
        coordinates.correlation_id().map(CorrelationId::as_str),
    )?;
    push_optional(&mut bytes, coordinates.request_id().map(RequestId::as_str))?;
    push_optional(
        &mut bytes,
        coordinates.operation_id().map(OperationId::as_str),
    )?;
    push_bytes(&mut bytes, event.context().payload().as_bytes())?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Error::RecordTooLarge);
    }
    Ok(bytes)
}

fn push_text(output: &mut Vec<u8>, value: &str) -> Result<(), Error> {
    push_bytes(output, value.as_bytes())
}

fn push_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), Error> {
    let len = u32::try_from(value.len()).map_err(|_| Error::RecordTooLarge)?;
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn push_optional(output: &mut Vec<u8>, value: Option<&str>) -> Result<(), Error> {
    match value {
        Some(value) => {
            output.push(1);
            push_text(output, value)
        }
        None => {
            output.push(0);
            Ok(())
        }
    }
}

/// Decode canonical V1 bytes after applying all structural and size checks.
///
/// The returned value is not source authentication, ledger authentication, or durable-commit
/// evidence. Use [`crate::verify_window`] to authenticate a supplied ledger range.
pub fn decode_untrusted(bytes: &[u8]) -> Result<DecodedAuditV1, Error> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(Error::RecordTooLarge);
    }
    let mut reader = Reader::new(bytes);
    if reader.take(DOMAIN.len())? != DOMAIN {
        return Err(Error::MalformedEncoding);
    }
    if reader.u16()? != RecordVersion::V1.tag() {
        return Err(Error::UnsupportedVersion);
    }
    let tenant = decode_tenant(reader.take(16)?)?;
    let source_id = SourceId::parse(reader.text(Field::SourceId, 64)?)?;
    let event_id = EventId::parse(reader.text(Field::EventId, 128)?)?;
    let contract_id = ContractId::parse(reader.text(Field::SourceContract, 255)?)
        .map_err(|_| Error::InvalidCharacter(Field::SourceContract))?;
    let contract_version =
        ContractVersion::from_major(reader.u32()?).map_err(|_| Error::MalformedEncoding)?;
    let schema_digest = SchemaDigest::parse(reader.text(Field::SourceContract, 71)?)
        .map_err(|_| Error::InvalidCharacter(Field::SourceContract))?;
    let actor_kind = ActorKind::parse(reader.text(Field::ActorKind, 64)?)?;
    let actor_id = ActorId::parse(reader.text(Field::ActorId, 512)?)?;
    let action = Action::parse(reader.text(Field::Action, 128)?)?;
    let resource_kind = ResourceKind::parse(reader.text(Field::ResourceKind, 64)?)?;
    let resource_id = ResourceId::parse(reader.text(Field::ResourceId, 512)?)?;
    let outcome = Outcome::from_tag(reader.u8()?).ok_or(Error::UnsupportedTag)?;
    let occurred_at = Timepoint::try_from(reader.i64()?).map_err(|_| Error::MalformedEncoding)?;
    let recorded_at = Timepoint::try_from(reader.i64()?).map_err(|_| Error::MalformedEncoding)?;
    let correlation_id = reader
        .optional_text(Field::CorrelationId, 128)?
        .map(CorrelationId::parse)
        .transpose()
        .map_err(|_| Error::InvalidCharacter(Field::CorrelationId))?;
    let request_id = reader
        .optional_text(Field::RequestId, 128)?
        .map(RequestId::parse)
        .transpose()
        .map_err(|_| Error::InvalidCharacter(Field::RequestId))?;
    let operation_id = reader
        .optional_text(Field::OperationId, 128)?
        .map(OperationId::parse)
        .transpose()?;
    let payload = AuditPayload::new(reader.bytes(Field::Payload, MAX_PAYLOAD_BYTES)?.to_vec())?;
    if !reader.is_finished() {
        return Err(Error::UnknownField);
    }
    let source = SourceIdentity::new(
        source_id,
        SourceContract::new(contract_id, contract_version, schema_digest),
    );
    let identity = RecordIdentity::new(tenant, source, event_id);
    let facts = EventFacts::new(
        ActorRef::new(actor_kind, actor_id),
        action,
        ResourceRef::new(resource_kind, resource_id),
        outcome,
        occurred_at,
    );
    let context = EventContext::new(
        Coordinates::new(correlation_id, request_id, operation_id),
        payload,
    );
    Ok(DecodedAuditV1::new(
        AuditEventV1::new(identity, facts, context),
        recorded_at,
    ))
}

fn decode_tenant(bytes: &[u8]) -> Result<TenantId, Error> {
    let mut value = String::with_capacity(36);
    for (index, byte) in bytes.iter().copied().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            value.push('-');
        }
        value.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        value.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    TenantId::parse(&value).map_err(|_| Error::MalformedEncoding)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(Error::MalformedEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::MalformedEncoding)?;
        self.offset = end;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::MalformedEncoding)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.fixed::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn i64(&mut self) -> Result<i64, Error> {
        Ok(i64::from_be_bytes(self.fixed()?))
    }

    fn bytes(&mut self, field: Field, max: usize) -> Result<&'a [u8], Error> {
        let len = usize::try_from(self.u32()?).map_err(|_| Error::MalformedEncoding)?;
        if len > max {
            return Err(if field == Field::Payload {
                Error::PayloadTooLarge
            } else {
                Error::TooLong(field)
            });
        }
        self.take(len)
    }

    fn text(&mut self, field: Field, max: usize) -> Result<&'a str, Error> {
        std::str::from_utf8(self.bytes(field, max)?).map_err(|_| Error::InvalidCharacter(field))
    }

    fn optional_text(&mut self, field: Field, max: usize) -> Result<Option<&'a str>, Error> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.text(field, max).map(Some),
            _ => Err(Error::UnsupportedTag),
        }
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
