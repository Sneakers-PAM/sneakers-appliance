-- Verifies the audit trail's hash chain on the moved sneakers_audit database,
-- before any service has started. It's the check VerifyChain makes in
-- sneakers-audit (internal/chain), in SQL: seq runs 1, 2, 3 with no gap, each
-- prev_hash is the record before's hash, and each hash recomputes from the
-- record's canonical form. Attribute keys sort by byte, as Go's sort.Strings
-- does, whatever the database's locale. It prints "ok", or the first bad seq,
-- which is all a failed move may show of the trail.
WITH walked AS (
  SELECT
    seq,
    hash,
    prev_hash,
    row_number() OVER (ORDER BY seq) AS position,
    coalesce(lag(hash) OVER (ORDER BY seq), '') AS previous,
    encode(sha256(convert_to(concat_ws('|',
      seq::text,
      CASE tier
        WHEN 0 THEN 'TIER_UNSPECIFIED'
        WHEN 1 THEN 'TIER_AUDIT'
        WHEN 2 THEN 'TIER_ACTIVITY'
        ELSE tier::text
      END,
      action,
      actor_user_id,
      subject,
      group_id,
      sensitive::text,
      coalesce((
        SELECT string_agg(a.key || '=' || a.value || ';', '' ORDER BY a.key COLLATE "C")
        FROM jsonb_each_text(attributes) AS a
      ), ''),
      occurred_at,
      prev_hash
    ), 'UTF8')), 'hex') AS computed
  FROM public.audit_records
)
SELECT coalesce(
  (SELECT 'broken at seq ' || min(seq)
     FROM walked
    WHERE seq <> position OR prev_hash <> previous OR hash <> computed
   HAVING count(*) > 0),
  'ok'
);
