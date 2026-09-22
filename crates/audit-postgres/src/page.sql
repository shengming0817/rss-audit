WITH selected AS MATERIALIZED (
    SELECT position, octet_length(canonical)::bigint AS bytes
    FROM rss_audit.records WHERE tenant_id=$1::uuid AND position>$2
    ORDER BY position LIMIT $3
), summary AS (
    SELECT count(*) AS count, COALESCE(sum(bytes),0) AS bytes,
        min(position) AS first, max(position) AS last,
        COALESCE(bool_and(bytes BETWEEN 1 AND 131072),true) AS valid
    FROM selected
), tail AS (
    SELECT COALESCE((SELECT position FROM rss_audit.heads WHERE tenant_id=$1::uuid),-1) AS position
), admission AS MATERIALIZED (
    SELECT CASE
        WHEN NOT s.valid OR s.count<>LEAST($3::numeric,GREATEST(t.position::numeric-$2,0))
          OR (s.count>0 AND (s.first::numeric<>$2::numeric+1 OR s.last::numeric<>$2::numeric+s.count)) THEN 2
        WHEN s.bytes>$4 THEN 1 ELSE 0 END AS status
    FROM summary s CROSS JOIN tail t
)
SELECT a.status,r.tenant_id::text,r.source_id,r.event_id,r.position,r.recorded_at,r.canonical,r.ledger_sequence
FROM admission a LEFT JOIN rss_audit.records r ON a.status=0 AND r.tenant_id=$1::uuid
    AND r.position IN (SELECT position FROM selected)
ORDER BY r.position
