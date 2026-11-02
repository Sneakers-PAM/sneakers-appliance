-- What a database holds, one line per thing, in an order that doesn't depend on
-- the cluster: every table's row count and a hash of its rows, its sequences,
-- and its objects. Two clusters holding the same data print the same text.
SELECT 'seq', schemaname, sequencename, last_value FROM pg_sequences ORDER BY 2, 3;
SELECT 'obj', n.nspname, c.relname, c.relkind, pg_get_userbyid(c.relowner)
  FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast') ORDER BY 2, 3;
SELECT format(
  $q$SELECT 'tbl', %L, count(*), coalesce(md5(string_agg(h, '' ORDER BY h COLLATE "C")), '-') FROM (SELECT md5(t::text) h FROM %I.%I t) s$q$,
  schemaname || '.' || tablename, schemaname, tablename)
  FROM pg_tables WHERE schemaname NOT IN ('pg_catalog', 'information_schema') ORDER BY schemaname, tablename
\gexec
