//! Strict public navigation input without provider or host state.
use rss_audit_http_axum::AuditQuery;
#[test]
fn query_defaults_are_bounded() -> anyhow::Result<()> {
    let query = AuditQuery::parse(None)?;
    assert_eq!(query.limit(), 50);
    assert!(!query.is_continuation());
    assert_eq!(AuditQuery::parse(Some("limit=100"))?.limit(), 100);
    for value in [
        "limit=0",
        "limit=101",
        "limit=1&limit=2",
        "tenantId=foreign",
        "limit=-1",
        "limit=4294967296",
        "cursor=",
        "limit=1.2",
        "cursor=a&cursor=b",
    ] {
        assert!(AuditQuery::parse(Some(value)).is_err(), "{value}");
    }
    assert!(AuditQuery::parse(Some(&"a".repeat(1025))).is_err());
    Ok(())
}
