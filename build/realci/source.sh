#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# source.sh: LAB ONLY, the earlier install the real-bundle job's import leg
# moves onto the box (docs/testing.md#the-import-leg): sneakers-release's
# synthetic source, with a large audit chain, in containers on the runner.
#
#   source.sh up                  a PostgreSQL and a Kratos container with the
#                                 original schema, seeded by the release's
#                                 synth (AUDIT_RECORDS audit records)
#   source.sh export <recipient> <out>
#                                 sneakers-migrate export of it, as the
#                                 appliance move takes it (current values,
#                                 sign-ins reset), encrypted to the box's
#                                 import key; prints its time and peak memory
#   source.sh down                removes the containers, their network and
#                                 the source's keys
#
# Inputs (environment):
#   RELEASE_SRC    the sneakers-release checkout the product under test is
#                  built from (its source schema and Kratos identity schema)
#   MIGRATE, SYNTH its sneakers-migrate and synth, built for the runner
#   WORK           a directory for the source's keys and summary (0700)
#   AUDIT_RECORDS  how many audit records synth chains (default 727000,
#                  more than the largest source measured: 726,805)
#   PREFIX         the containers' name prefix (default realci-source)
# The keys synth makes are invented for the run; nothing here is a real
# system's, and none of it is printed.
set -euo pipefail
: "${RELEASE_SRC:?}" "${MIGRATE:?}" "${SYNTH:?}" "${WORK:?}"
prefix="${PREFIX:-realci-source}"
records="${AUDIT_RECORDS:-727000}"
owner="owner@example.org"
# The same images sneakers-release's rehearsal runs its source on.
pg_image="docker.io/library/postgres:18.6@sha256:5a5a84b19854a9ffaa54082c166ff4ec27473a361e496e5ea167f298f2da9722"
kratos_image="oryd/kratos:v1.3.1@sha256:fe2428f103a6240c064b6ea77d3088610865c55fcebccb30355857eccdc25b4b"
say() { echo "realci: source: $*"; }
mkdir -p "$WORK"
chmod 700 "$WORK"
env_file="$WORK/source.env"

up() {
  local pw start kdsn pg_port k_port
  start="$(date +%s)"
  pw="$(openssl rand -hex 16)"
  docker network create "$prefix-net" >/dev/null
  docker run -d --name "$prefix-pg" --network "$prefix-net" -e POSTGRES_PASSWORD="$pw" -p 127.0.0.1::5432 "$pg_image" >/dev/null
  for _ in $(seq 60); do docker exec "$prefix-pg" pg_isready -U postgres -q 2>/dev/null && break; sleep 1; done
  sleep 2
  for d in src_identity src_vault src_workflow src_audit src_kratos; do
    docker exec "$prefix-pg" createdb -U postgres "$d"
  done
  mkdir -p "$WORK/kratos"
  python3 - "$RELEASE_SRC/charts/sneakers/values.yaml" "$WORK/kratos" <<'PY'
import sys, yaml
values = yaml.safe_load(open(sys.argv[1]))
schema = values["kratos"]["kratos"]["identitySchemas"]["identity.default.schema.json"]
open(sys.argv[2] + "/identity.schema.json", "w").write(schema)
cfg = {
    "serve": {"public": {"base_url": "http://127.0.0.1:4433/"}, "admin": {"base_url": "http://127.0.0.1:4434/"}},
    "identity": {"default_schema_id": "default", "schemas": [{"id": "default", "url": "file:///etc/kratos/identity.schema.json"}]},
    "selfservice": {"default_browser_return_url": "https://source.example.org/", "methods": {"password": {"enabled": True}}},
    "courier": {"smtp": {"connection_uri": "smtp://smtp.example.org:25/"}},
}
open(sys.argv[2] + "/kratos.yml", "w").write(yaml.safe_dump(cfg))
PY
  chmod 755 "$WORK/kratos"
  chmod 644 "$WORK/kratos"/*
  kdsn="postgres://postgres:${pw}@${prefix}-pg:5432/src_kratos?sslmode=disable"
  docker run --rm --network "$prefix-net" -v "$WORK/kratos:/etc/kratos:ro" -e DSN="$kdsn" "$kratos_image" migrate sql -e --yes -c /etc/kratos/kratos.yml >/dev/null 2>&1
  docker run -d --name "$prefix-kratos" --network "$prefix-net" -v "$WORK/kratos:/etc/kratos:ro" -e DSN="$kdsn" -p 127.0.0.1::4434 "$kratos_image" serve -c /etc/kratos/kratos.yml >/dev/null
  pg_port="$(docker port "$prefix-pg" 5432/tcp | head -1 | cut -d: -f2)"
  k_port="$(docker port "$prefix-kratos" 4434/tcp | head -1 | cut -d: -f2)"
  for _ in $(seq 60); do curl -fs "http://127.0.0.1:${k_port}/admin/health/ready" >/dev/null && break; sleep 1; done
  {
    for s in identity vault workflow audit; do
      echo "SOURCE_${s^^}_DSN=postgres://postgres:${pw}@127.0.0.1:${pg_port}/src_${s}?sslmode=disable"
    done
    echo "SOURCE_KRATOS_ADMIN_URL=http://127.0.0.1:${k_port}"
  } > "$env_file"
  chmod 600 "$env_file"
  (
    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
    "$SYNTH" -s "$RELEASE_SRC/migrate/testdata/source-schema" -k "$WORK/source-keys.json" -o "$WORK/source-summary.json" -e "$owner" -a "$records" >/dev/null
  )
  python3 - "$WORK/source-summary.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1]))
r = s["Rows"]
print("realci: source: seeded %d Kratos identities, %d users, %d secrets, %d audit records"
      % (s["Kratos"], r["identity.users"], r["vault.secrets"], r["audit.audit_records"]))
PY
  say "audit records $(docker exec "$prefix-pg" psql -U postgres -d src_audit -qtAX -c "SELECT count(*) || ' rows, ' || pg_size_pretty(pg_total_relation_size('audit_records')) || ' on disk, ' || round(avg(pg_column_size(a.*))) || ' bytes a row' FROM audit_records a")"
  say "up in $(( $(date +%s) - start ))s"
}

export_to() {
  local rcpt="$1" out="$2" start status=0
  start="$(date +%s)"
  (
    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
    keys() { python3 -c "import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$WORK/source-keys.json" "$1"; }
    export SOURCE_VAULT_ROOT_KEK SOURCE_DEV_KEK_SEED
    SOURCE_VAULT_ROOT_KEK="$(keys SOURCE_VAULT_ROOT_KEK)" SOURCE_DEV_KEK_SEED="$(keys SOURCE_DEV_KEK_SEED)"
    # Its peak resident memory, from the kernel's accounting once it ends.
    exec python3 -c '
import resource, subprocess, sys
code = subprocess.call(sys.argv[1:])
print("peak RSS %d MiB" % (resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss // 1024), file=sys.stderr)
sys.exit(code)' "$MIGRATE" export --recipient "$rcpt" --out "$out" --current-only --reset-sign-in
  ) > "$WORK/export.txt" 2>&1 || status=$?
  sed -n '/^parity/,/^  connections/p' "$WORK/export.txt"
  [ "$status" = 0 ] || { tail -20 "$WORK/export.txt" >&2; echo "realci: source: export failed ($status)" >&2; exit 1; }
  say "export: $(stat -c %s "$out") bytes in $(( $(date +%s) - start ))s, $(grep -o 'peak RSS [0-9]* MiB' "$WORK/export.txt")"
}

down() {
  docker rm -f "$prefix-kratos" "$prefix-pg" >/dev/null 2>&1 || true
  docker network rm "$prefix-net" >/dev/null 2>&1 || true
  rm -f "$WORK/source-keys.json" "$env_file"
  say "down"
}

case "${1:-}" in
  up) up ;;
  export) [ $# -eq 3 ] || { echo "usage: source.sh export <recipient> <out>" >&2; exit 2; }; export_to "$2" "$3" ;;
  down) down ;;
  *) echo "usage: source.sh up | export <recipient> <out> | down" >&2; exit 2 ;;
esac
