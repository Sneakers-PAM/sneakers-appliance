-- Seeds one of the product's databases with invented rows, run as the role that
-- owns it, on top of the tables the service made for itself: a bit of everything
-- a dump has to carry. :rows is set by rehearsal.sh.
CREATE SCHEMA IF NOT EXISTS rehearsal;
CREATE TABLE rehearsal.items (
  id bigserial PRIMARY KEY,
  label text NOT NULL,
  body bytea,
  doc jsonb,
  at timestamptz DEFAULT now()
);
CREATE TABLE rehearsal."Odd Name" (id int PRIMARY KEY, parent bigint REFERENCES rehearsal.items(id));
CREATE INDEX items_label ON rehearsal.items (label);
CREATE VIEW rehearsal.recent AS SELECT id, label FROM rehearsal.items ORDER BY label LIMIT 10;
INSERT INTO rehearsal.items (label, body, doc)
SELECT
  (ARRAY['Émile', 'zoë', 'Zed', 'adam', 'Ångström', 'o''brien'])[g % 6 + 1] || md5(g::text),
  decode(repeat(md5(g::text), 40), 'hex'),
  jsonb_build_object('n', g, 'name', md5((g * 7)::text), 'tags', jsonb_build_array('a', g % 11))
FROM generate_series(1, :rows) g;
INSERT INTO rehearsal."Odd Name" SELECT g, g FROM generate_series(1, 100) g;
