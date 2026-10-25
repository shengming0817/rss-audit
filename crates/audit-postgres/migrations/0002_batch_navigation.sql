-- Run once as the existing migration owner, in one transaction with writers stopped.
-- Historical positions and authenticated bytes are unchanged; positions now mean navigation only.
LOCK TABLE rss_audit.records IN ACCESS EXCLUSIVE MODE;
CREATE SEQUENCE rss_audit.positions AS bigint MINVALUE 0 START 0 NO CYCLE;
DO $position$
DECLARE last_position bigint;
BEGIN
 SELECT max(position) INTO last_position FROM rss_audit.records;
 IF last_position=9223372036854775807 THEN RAISE EXCEPTION 'audit position exhausted' USING ERRCODE='PA002'; END IF;
 PERFORM setval('rss_audit.positions',COALESCE(last_position+1,0),false);
END $position$;
ALTER TABLE rss_audit.records DROP CONSTRAINT records_tenant_id_fkey;
CREATE FUNCTION rss_audit.append_batch(p_tenant uuid,p_sources text[],p_events text[],
 p_recorded bigint[],p_canonical bytea[],p_ledger bigint[])
RETURNS TABLE(source_id text,event_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,rss_audit AS $append$
BEGIN
 IF p_tenant IS DISTINCT FROM NULLIF(current_setting('rss.tenant_id',true),'')::uuid THEN
  RAISE EXCEPTION 'audit tenant mismatch' USING ERRCODE='PA001';
 END IF;
 IF cardinality(p_sources) IS NULL OR cardinality(p_events) IS DISTINCT FROM cardinality(p_sources)
 OR cardinality(p_recorded) IS DISTINCT FROM cardinality(p_sources)
 OR cardinality(p_canonical) IS DISTINCT FROM cardinality(p_sources)
 OR cardinality(p_ledger) IS DISTINCT FROM cardinality(p_sources) THEN
  RAISE EXCEPTION 'invalid audit batch' USING ERRCODE='PA002';
 END IF;
 RETURN QUERY
 INSERT INTO rss_audit.records AS r(tenant_id,source_id,event_id,position,recorded_at,canonical,ledger_sequence)
 SELECT p_tenant,i.source_id,i.event_id,nextval('rss_audit.positions'),i.recorded,i.canonical,i.ledger
 FROM unnest(p_sources,p_events,p_recorded,p_canonical,p_ledger)
 AS i(source_id,event_id,recorded,canonical,ledger)
 ORDER BY i.source_id COLLATE "C",i.event_id COLLATE "C"
 ON CONFLICT ON CONSTRAINT records_pkey DO NOTHING
 RETURNING r.source_id,r.event_id;
END $append$;
REVOKE ALL ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) FROM PUBLIC;
REVOKE ALL ON SEQUENCE rss_audit.positions FROM PUBLIC;
-- Carry writer grants to the replacement, never grant reader credentials append authority.
DO $grants$
DECLARE role_grant record;
BEGIN
 FOR role_grant IN
 SELECT r.rolname,a.is_grantable FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
 JOIN pg_roles r ON r.oid=a.grantee
 WHERE p.oid='rss_audit.append(uuid,text,text,bigint,bytea,bigint)'::regprocedure AND a.privilege_type='EXECUTE'
 LOOP
  EXECUTE format('GRANT EXECUTE ON FUNCTION rss_audit.append_batch(uuid,text[],text[],bigint[],bytea[],bigint[]) TO %I%s',role_grant.rolname,CASE WHEN role_grant.is_grantable THEN ' WITH GRANT OPTION' ELSE '' END);
 END LOOP;
END $grants$;
DROP FUNCTION rss_audit.append(uuid,text,text,bigint,bytea,bigint);
DROP FUNCTION rss_audit.reserve(uuid);
DROP TABLE rss_audit.heads;
