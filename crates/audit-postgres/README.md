# rss-audit-postgres

Fresh PostgreSQL 16+ Audit persistence. The host supplies a pool, monotonic timer,
absolute deadline, cancellation and explicit `Integrity::Plain` or `Integrity::Ledger(auth)`.
No migration execution, pool shutdown, global reads, memory provider or automatic downgrade.
The `ledger` and `messaging` features are independently additive; `integration` is test-only.

## Ownership and retry

`PgAudit::prepare(event, control)` obtains `recorded_at` from PostgreSQL in V1 Unix seconds.
It returns `PreparedAuditV1`, not a write receipt. Preserve these exact canonical bytes durably
in the source's retry/outbox state before an append can become uncertain. Recreating an event
with a new recording time after commit-unknown is a different request and correctly conflicts.
`PreparedAuditV1::from_canonical_bytes` restores structurally valid bytes; it authenticates
neither their source nor the recording-time assertion. Source adapters remain trusted.

`append` returns canonical `LocalTxAttempt<Committed<StagedAppend>, Error>`. Only the private
`Committed` constructor follows an acknowledged database COMMIT. Successful staging, an error,
an absent read, `CommitUnknown` and `RollbackFailed` are not rollback evidence. Retry the
unchanged prepared request to serialize recovery. Database errors remain redacted.

`local_tx(tenant, control, callback)` combines Audit with trusted business SQL via
`AuditTransaction::with_connection`. A callback returning `Result<R, E>` produces
`LocalTxAttempt<Committed<R>, TransactionError<E>>`: `Operation(E)` retains the original
host reason/classification, `Audit(Error)` identifies adapter/control failures, and
`Rollback { operation, settlement }` retains both causes when rollback is unconfirmed.
`E` needs no formatting or error trait; diagnostics never render or traverse it. Match it
explicitly to recover its typed value. `with_connection` likewise preserves its callback's
error type. There is no untyped business-rejection sentinel or error side channel.
Errors must propagate. This is not a SQL sandbox:
do not issue transaction control, change role/tenant/session state, or swallow append errors.
Lock order is Audit tenant head → ledger → business/outbox. One absolute budget covers
acquisition, setup, operation and settlement. Unconfirmed connections are closed, never reused.
Cancellation after the callback returns an error cannot overwrite that error. If cancellation
prevents rollback from starting, the result is `RollbackFailed` with both causes, not
`CommitUnknown`: this branch never attempted commit. Only a real rollback ACK permits
`RolledBack`. No fresh cleanup budget is minted.

With `messaging`, `append_in(&mut PgTransaction, &prepared)` borrows the actual message connection,
inherits its tenant and remaining budget, and changes no GUC, isolation level or lifecycle state.
It does not use this Audit object's pool. Its result is staged; only the original message owner
can settle Inbox/business/Audit/ledger together and mint ACK authority. Return failures through
that owner; original `PgError` classification, including ownership loss, is preserved.

## Integrity and reads

Stable identity is `(tenant, source_id, event_id)`. Exact bytes and stored integrity mode
must agree on replay. The host may choose another mode for a new event in the same tenant;
there is no permanent tenant-mode pin. Ledger failure aborts; it never retries plain.
HMAC, chain ordering and key admission remain owned by RSS ledger.

`read_page(Cursor, ReadLimit, control)` uses a separate monotonic Audit position. It structurally
checks bytes and index metadata without authentication. Supply 1..=1024 rows and a positive
canonical-byte budget. SQL preflights the complete selected page before returning payloads;
oversized pages return no partial rows. The cursor advances after the final returned row;
an empty page has no cursor. Appends between calls may appear: this is not a multi-page snapshot.

With `ledger`, `read_verified(tenant, Sequence, ledger::ReadLimit, control)` authenticates a window
and checks its Audit-row association. Its budget charges ledger encoded bytes, including the
predecessor. Ordinary cursors and ledger sequences are not interchangeable. Plain rows are not
in the ledger window. Verification does not prove source truth, complete Audit history, absence
of tail truncation or an external checkpoint.

## Installation and roles

`MIGRATION_SQL` creates only a fresh `rss_audit` schema: no legacy probing, backfill, compatibility
ALTER path or automatic repair. Run it as a separately provisioned NOLOGIN NOSUPERUSER NOBYPASSRLS
NOCREATEROLE owner. Runtime must not own objects, switch to an owner/privileged role, have
CREATE/delegation rights, or access Audit objects through PUBLIC. Grant only:

```sql
GRANT USAGE ON SCHEMA rss_audit TO audit_runtime;
GRANT SELECT ON ALL TABLES IN SCHEMA rss_audit TO audit_runtime;
GRANT EXECUTE ON FUNCTION rss_audit.reserve(uuid),
    rss_audit.append(uuid,text,text,bigint,bytea,bigint) TO audit_runtime;
```

Runtime cannot INSERT/UPDATE/DELETE/TRUNCATE tables. Fixed SECURITY DEFINER functions enforce
tenant scope, acquire the serialization lock and append. Both tables FORCE RLS, including for
their owner. Ledger and transactional-messaging installations/grants remain separately owned.
The host must configure authenticated TLS; Audit does not accept a URL or replace pool settings.
Admission checks actual role, inherited/switchable access, columns, constraints, RLS, definer
bodies/configuration, durability and privileges. Unexpected drift fails closed. Privileged
operators can still alter storage; Audit provides no WORM, retention/hold, key custody or DR policy.

ref: launchbadge/sqlx sqlx-core/src/transaction.rs@v0.9.0
ref: sea-ql/sea-orm TransactionError<E>@2.0.2 (typed callback error, not settlement authority)
