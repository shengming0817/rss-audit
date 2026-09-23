use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rss_audit_postgres::Cursor;
use rss_request_context::TenantId;
use serde::Deserialize;

/// Validated navigation only. Tenant authority never comes from this value.
pub struct AuditQuery {
    limit: u32,
    cursor: Option<Cursor>,
}
/// Invalid bounded query; rejected values are never retained.
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("invalid audit query")]
pub struct InvalidQuery;
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WireQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}
impl AuditQuery {
    /// Parse the only accepted query parameters within a 1 KiB input bound.
    pub fn parse(query: Option<&str>) -> Result<Self, InvalidQuery> {
        let query = query.unwrap_or_default();
        if query.len() > 1024 {
            return Err(InvalidQuery);
        }
        let wire: WireQuery = serde_urlencoded::from_str(query).map_err(|_| InvalidQuery)?;
        let limit = wire.limit.unwrap_or(50);
        if !(1..=100).contains(&limit) {
            return Err(InvalidQuery);
        }
        Ok(Self {
            limit,
            cursor: wire.cursor.as_deref().map(decode).transpose()?,
        })
    }
    /// Requested complete-page row bound.
    pub const fn limit(&self) -> u32 {
        self.limit
    }
    /// Whether this is a continuation rather than a fresh first page.
    pub const fn is_continuation(&self) -> bool {
        self.cursor.is_some()
    }
    pub(crate) fn cursor(&self, tenant: TenantId) -> Result<Cursor, InvalidQuery> {
        match self.cursor {
            Some(cursor) if cursor.tenant() != tenant => Err(InvalidQuery),
            Some(cursor) => Ok(cursor),
            None => Ok(Cursor::start(tenant)),
        }
    }
}
fn decode(value: &str) -> Result<Cursor, InvalidQuery> {
    // 1 version + 16 tenant + 8 after + 8 inclusive upper; no padding or alternate encodings.
    if value.len() != 44 {
        return Err(InvalidQuery);
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| InvalidQuery)?;
    if bytes.len() != 33 || bytes[0] != 1 || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(InvalidQuery);
    }
    let hex: String = bytes[1..17].iter().map(|b| format!("{b:02x}")).collect();
    let tenant = TenantId::parse(&format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
    .map_err(|_| InvalidQuery)?;
    let after = u64::from_be_bytes(bytes[17..25].try_into().map_err(|_| InvalidQuery)?);
    let through = u64::from_be_bytes(bytes[25..33].try_into().map_err(|_| InvalidQuery)?);
    Cursor::resume(tenant, after, through).map_err(|_| InvalidQuery)
}
pub(crate) fn encode(cursor: Cursor) -> Result<String, rss_audit_postgres::Error> {
    let (after, through) = cursor
        .continuation()
        .ok_or(rss_audit_postgres::Error::StorageContract)?;
    let mut bytes = Vec::with_capacity(33);
    bytes.push(1);
    bytes.extend_from_slice(&cursor.tenant().octets());
    bytes.extend_from_slice(&after.to_be_bytes());
    bytes.extend_from_slice(&through.to_be_bytes());
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cursor_is_canonical_tenant_bound_and_lossless() -> anyhow::Result<()> {
        let tenant = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d479")?;
        let other = TenantId::parse("f47ac10b-58cc-4372-a567-0e02b2c3d480")?;
        let cursor = Cursor::resume(tenant, 9_007_199_254_740_992, i64::MAX as u64)?;
        let token = encode(cursor)?;
        assert_eq!(decode(&token)?.continuation(), cursor.continuation());
        let q = AuditQuery::parse(Some(&format!("cursor={token}&limit=100")))?;
        assert!(q.is_continuation());
        assert_eq!(q.cursor(tenant)?, cursor);
        assert!(q.cursor(other).is_err());
        assert!(encode(Cursor::start(tenant)).is_err());
        for bad in [
            "".into(),
            "x".repeat(44),
            format!("{token}="),
            token[..43].to_owned(),
        ] {
            assert!(decode(&bad).is_err());
        }
        for index in [0, 17, 25] {
            let mut bytes = URL_SAFE_NO_PAD.decode(&token)?;
            bytes[index] = 255;
            assert!(decode(&URL_SAFE_NO_PAD.encode(bytes)).is_err());
        }
        let mut nil = URL_SAFE_NO_PAD.decode(&token)?;
        nil[1..17].fill(0);
        assert!(decode(&URL_SAFE_NO_PAD.encode(nil)).is_err());
        Ok(())
    }
}
