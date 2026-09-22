-- Fresh schema only. The current migration role must be NOLOGIN NOSUPERUSER NOBYPASSRLS.
-- Provision runtime separately; grant USAGE, SELECT and the two functions below, never DML.
CREATE SCHEMA rss_audit;
REVOKE ALL ON SCHEMA rss_audit FROM PUBLIC;
CREATE TABLE rss_audit.heads (
    tenant_id uuid PRIMARY KEY,
    position bigint CHECK (position >= 0)
);
CREATE TABLE rss_audit.records (
    tenant_id uuid NOT NULL REFERENCES rss_audit.heads(tenant_id),
    source_id text COLLATE "C" NOT NULL CHECK (octet_length(source_id) BETWEEN 1 AND 64),
    event_id text COLLATE "C" NOT NULL CHECK (octet_length(event_id) BETWEEN 1 AND 128),
    position bigint NOT NULL CHECK (position >= 0),
    recorded_at bigint NOT NULL CHECK (recorded_at >= 0),
    canonical bytea NOT NULL CHECK (octet_length(canonical) BETWEEN 1 AND 131072),
    ledger_sequence bigint CHECK (ledger_sequence >= 0),
    PRIMARY KEY (tenant_id, source_id, event_id),
    UNIQUE (tenant_id, position),
    UNIQUE (tenant_id, ledger_sequence)
);
ALTER TABLE rss_audit.heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_audit.heads FORCE ROW LEVEL SECURITY;
ALTER TABLE rss_audit.records ENABLE ROW LEVEL SECURITY;
ALTER TABLE rss_audit.records FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON rss_audit.heads
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
CREATE POLICY tenant_scope ON rss_audit.records
    USING (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('rss.tenant_id', true), '')::uuid);
REVOKE ALL ON ALL TABLES IN SCHEMA rss_audit FROM PUBLIC;

CREATE FUNCTION rss_audit.reserve(p_tenant uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, rss_audit AS $reserve$
BEGIN
    IF p_tenant IS DISTINCT FROM NULLIF(current_setting('rss.tenant_id', true), '')::uuid THEN
        RAISE EXCEPTION 'audit tenant mismatch' USING ERRCODE = 'PA001';
    END IF;
    INSERT INTO rss_audit.heads(tenant_id) VALUES (p_tenant) ON CONFLICT DO NOTHING;
    PERFORM 1 FROM rss_audit.heads WHERE tenant_id = p_tenant FOR UPDATE;
END
$reserve$;

CREATE FUNCTION rss_audit.append(p_tenant uuid, p_source text, p_event text,
    p_recorded bigint, p_canonical bytea, p_ledger bigint) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, rss_audit AS $append$
DECLARE
    previous bigint;
    allocated bigint;
BEGIN
    IF p_tenant IS DISTINCT FROM NULLIF(current_setting('rss.tenant_id', true), '')::uuid THEN
        RAISE EXCEPTION 'audit tenant mismatch' USING ERRCODE = 'PA001';
    END IF;
    SELECT position INTO previous FROM rss_audit.heads WHERE tenant_id = p_tenant FOR UPDATE;
    IF NOT FOUND OR previous = 9223372036854775807 THEN
        RAISE EXCEPTION 'audit position unavailable' USING ERRCODE = 'PA002';
    END IF;
    allocated := COALESCE(previous + 1, 0);
    INSERT INTO rss_audit.records VALUES
        (p_tenant, p_source, p_event, allocated, p_recorded, p_canonical, p_ledger);
    UPDATE rss_audit.heads SET position = allocated WHERE tenant_id = p_tenant;
    RETURN allocated;
END
$append$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rss_audit FROM PUBLIC;
