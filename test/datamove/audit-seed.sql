-- Appends a valid stretch of hash chain to the real audit_records table, in the
-- form datamove/audit-chain.sql checks, after whatever the audit service wrote.
DO $$
DECLARE
  s bigint;
  prev text;
  at text;
  attrs jsonb;
  h text;
BEGIN
  SELECT coalesce(max(seq), 0), coalesce((SELECT hash FROM public.audit_records ORDER BY seq DESC LIMIT 1), '')
    INTO s, prev FROM public.audit_records;
  FOR i IN 1..current_setting('rehearsal.records')::int LOOP
    s := s + 1;
    at := to_char(timestamp '2026-01-01' + (i || ' seconds')::interval, 'YYYY-MM-DD"T"HH24:MI:SS"Z"');
    attrs := jsonb_build_object('b', i::text, 'a', 'zoë', 'Z', 'Ångström');
    h := encode(sha256(convert_to(concat_ws('|',
      s::text, 'TIER_AUDIT', 'secret.read', 'user-' || (i % 50), 'subject-' || i, 'group-' || (i % 7), (i % 3 = 0)::text,
      (SELECT string_agg(a.key || '=' || a.value || ';', '' ORDER BY a.key COLLATE "C") FROM jsonb_each_text(attrs) AS a),
      at, prev), 'UTF8')), 'hex');
    INSERT INTO public.audit_records (seq, tier, action, actor_user_id, subject, group_id, sensitive, attributes, occurred_at, prev_hash, hash)
    VALUES (s, 1, 'secret.read', 'user-' || (i % 50), 'subject-' || i, 'group-' || (i % 7), i % 3 = 0, attrs, at, prev, h);
    prev := h;
  END LOOP;
END
$$;
