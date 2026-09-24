# rss-audit-http-axum

Embeddable tenant-only audit queries. The host supplies an admitted `PgAudit`, a mandatory
`AuditQueryPolicy<S>`, a monotonic `ExecutionTimer`, and per-request `Arc<S>` authenticated evidence
and `AuditRequestBudget` extensions. No Identity dependency, credential parsing, listener, TLS,
readiness, migrations, pool ownership or implicit authorization.

`GET /api/v2/audit/entries?limit=50&cursor=...` accepts only `limit` (1..=100, default 50) and
`cursor`; query text is bounded to 1024 bytes. A cursor is unpadded canonical base64url of version
byte 1, 16 tenant bytes, big-endian u64 after and inclusive through. It is navigation, not authority.
The first page captures a fixed upper bound. The final/empty page has `nextCursor: null`.
Concurrent appends, including self-audit, do not extend the enumeration; this is not an MVCC
snapshot, authenticated checkpoint, or complete-history proof. Start a new query to see new records.

The response is `{tenantId, integrity: "unverified", entries, nextCursor}`. Entries contain only
`position`, `sourceId`, `eventId`, `action`, `outcome` (`succeeded|denied|failed|unknown`), `occurredAt`,
`recordedAt`, and nullable `ledger: {chainId, recordId, sequence}`. All 64-bit values are canonical
decimal strings; times are nonnegative Unix seconds. Position is not ledger sequence. Ledger
coordinates do not authenticate records. Actor/resource references, correlation/request/operation
IDs, payload, raw canonical bytes and credentials are never serialized. Source products remain
responsible for non-secret source/event/action identifiers. Responses carry `Cache-Control: no-store`.

Policy checks session freshness and whole-tenant query permission on every request. It is a
bounded synchronous decision, not blocking I/O. Authentication and preparation happen in the host,
using the same incoming deadline. The grant explicitly selects `SelfAudit::NotRequired` or
`SelfAudit::Required(prepared)`. For Required, the host durably preserves the exact prepared bytes
and stable event ID before dispatch. This type does not prove durable preservation. In one tenant
transaction the adapter selects the page, then appends the query attempt. Only a confirmed COMMIT
permits returning the page. An audit record must not claim the HTTP client received the response.

Never wrap the transaction handler in a timeout that drops its future. Propagate the host token
and absolute deadline and await the classified outcome. `QueryOutcome` in response extensions
retains the canonical attempt as server-side diagnostics, not new commit evidence. Remove it and
use `try_into_attempt` to inspect it; release any extension clones first. No automatic retry occurs.
A dropped handler has no response or extension; the provider retires its unresolved connection,
and the host must recover uncertainty from its durable original intent without changing bytes.
Denied/failed-request auditing, retry orchestration and client-delivery evidence are host-owned.

Safe errors use RSS `{error:{code,message}}`: input/cursor 400, missing/expired authentication 401,
policy denial 403, internal/storage contract violations 500, unavailable/timeout/cancel/uncertain
settlement 503. Hosts add the appropriate 401 challenge. Missing budget is a host error (500).
No old route, DTO, hash algorithm, admin pool, cross-tenant API or verified-query API is provided.

ref: tokio-rs/axum axum/src/extension.rs@axum-v0.8.9
