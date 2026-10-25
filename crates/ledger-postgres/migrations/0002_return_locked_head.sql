-- Stop writers and run as the existing Ledger migration owner. No authenticated data changes.
-- ref: PostgreSQL REL_17_6 src/backend/executor/nodeLockRows.c
DO $upgrade$
DECLARE definition text; grants text;
BEGIN
 SELECT string_agg(format('GRANT EXECUTE ON FUNCTION rss_ledger.prepare_append(uuid,text,text,smallint) TO %I%s;',r.rolname,CASE WHEN a.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END), E'\n') INTO grants
 FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_roles r ON r.oid=a.grantee
 WHERE p.oid='rss_ledger.prepare_append(uuid,text,text,smallint)'::regprocedure AND a.privilege_type='EXECUTE';
 DROP FUNCTION rss_ledger.prepare_append(uuid,text,text,smallint);
 definition := $definition$CREATE FUNCTION rss_ledger.prepare_append(t uuid,c text,k text,v smallint) RETURNS rss_ledger.heads
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_ledger AS $$
DECLARE h rss_ledger.heads;
BEGIN
    IF t IS DISTINCT FROM nullif(current_setting('rss.tenant_id',true),'')::uuid THEN
        RAISE EXCEPTION 'ledger scope mismatch' USING ERRCODE='PL001';
    END IF;
    INSERT INTO rss_ledger.heads VALUES(t,c,k,v,NULL,decode(repeat('00',32),'hex')) ON CONFLICT DO NOTHING;
    SELECT * INTO STRICT h FROM rss_ledger.heads WHERE tenant_id=t AND chain_id=c FOR UPDATE;
    IF h.key_id<>k THEN RAISE EXCEPTION 'ledger key mismatch' USING ERRCODE='PL002'; END IF;
    IF h.encoding_version<>v THEN RAISE EXCEPTION 'ledger version mismatch' USING ERRCODE='PL003'; END IF;
    RETURN h;
END $$;

CREATE OR REPLACE FUNCTION rss_ledger.insert_entry(t uuid,c text,r text,s bigint,p bytea,a bytea,b bytea,k text,v smallint) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_ledger AS $$
DECLARE h rss_ledger.heads;
BEGIN
    SELECT * INTO STRICT h FROM rss_ledger.prepare_append(t,c,k,v);
    IF h.seq=9223372036854775807 THEN RAISE EXCEPTION 'ledger exhausted' USING ERRCODE='PL004'; END IF;
    IF s IS DISTINCT FROM coalesce(h.seq+1,0) OR p IS DISTINCT FROM h.tag THEN
        RAISE EXCEPTION 'ledger predecessor mismatch' USING ERRCODE='PL005';
    END IF;
    INSERT INTO rss_ledger.entries VALUES(t,c,r,s,p,a,b,v,k);
    UPDATE rss_ledger.heads SET seq=s,tag=a WHERE tenant_id=t AND chain_id=c;
END $$;
$definition$;
 EXECUTE definition;
 REVOKE ALL ON FUNCTION rss_ledger.prepare_append(uuid,text,text,smallint) FROM PUBLIC;
 IF grants IS NOT NULL THEN EXECUTE grants; END IF;
END $upgrade$;
