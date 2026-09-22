//! Public read-bound validation.
use rss_audit_postgres::{Cursor, ReadLimit};
use rss_request_context::TenantId;

#[test]
fn caller_must_supply_both_valid_page_budgets() -> anyhow::Result<()> {
    assert!(ReadLimit::new(0, 1).is_err());
    assert!(ReadLimit::new(1025, 1).is_err());
    assert!(ReadLimit::new(1, 0).is_err());
    assert!(ReadLimit::new(1, u64::MAX).is_err());
    assert!(ReadLimit::new(1024, 131_072).is_ok());
    let tenant = TenantId::parse("018f47c2-8bd8-7f21-a52b-8d4f6ee2b203")?;
    assert!(Cursor::after(tenant, u64::MAX).is_err());
    assert_eq!(Cursor::start(tenant).tenant(), tenant);
    Ok(())
}
