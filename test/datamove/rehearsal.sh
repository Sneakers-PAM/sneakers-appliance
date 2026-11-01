#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# rehearsal.sh: the data move against the real charts on a throwaway kind
# cluster (docs/data-move.md#testing-it). The old cluster, with the real
# services on it, is seeded; sneakers-pgha comes up beside it in the same
# release, as a bundle places it, with the box's own values and the certificate
# the box issues;
# then the real internal/datamove is SIGKILLed mid-dump, mid-restore and just
# before the switch. Each time the old cluster has to hold exactly what it held
# and the services have to start on it. The last run goes through, every table
# is compared, and the services start on the new cluster over TLS.
#
# Inputs (environment):
#   CHARTS      a sneakers-release checkout whose test/kind/build-images.sh
#               built and loaded the service images
#   WORK_DIR    a scratch directory (default: a new one)
#   SEED_ROWS   rows in each database's seeded table (default 100000, about
#               120 MiB in all)
#   AUDIT_ROWS  audit records to chain (default 20000)
#   SKIP_WEB    1 leaves the two web apps out, where they weren't built
#
# It runs against the current kubectl context and refuses any that isn't kind-*.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${CHARTS:?CHARTS is a sneakers-release checkout}"
work="${WORK_DIR:-$(mktemp -d)}"
mkdir -p "$work"
rows="${SEED_ROWS:-100000}"
audit_rows="${AUDIT_ROWS:-20000}"
ns=sneakers
fail() { echo "FAIL: $*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }
ctx="$(kubectl config current-context)"
case "$ctx" in kind-*) ;; *) fail "the context $ctx isn't a kind cluster" ;; esac

results="$work/results.txt"
: > "$results"
note() { echo "$*" | tee -a "$results"; }

k() { kubectl -n "$ns" "$@"; }
databases=(sneakers_identity sneakers_vault sneakers_workflow sneakers_audit sneakers_kratos sneakers_hydra)
web=()
if [ "${SKIP_WEB:-}" = 1 ]; then web=(--set web-staff.enabled=false --set web-admin.enabled=false); fi

psql_in() { # pod database: runs its standard input as postgres over the local socket
  k exec -i "$1" -c postgres -- psql -U postgres -d "$2" -qtAX -v ON_ERROR_STOP=1 -f -
}

snapshot() { # pod output
  local db
  {
    psql_in "$1" postgres <<'SQL'
SELECT 'db', datname, pg_get_userbyid(datdba), pg_encoding_to_char(encoding), datcollate, datctype
  FROM pg_database WHERE datname LIKE 'sneakers\_%' ORDER BY 2;
SELECT 'role', rolname, rolsuper, rolcanlogin, coalesce(split_part(rolpassword, '$', 1), '')
  FROM pg_authid WHERE rolname = 'sneakers';
SQL
    for db in "${databases[@]}"; do
      echo "# $db"
      psql_in "$1" "$db" < "$here/snapshot.sql"
    done
  } > "$2"
}

start_services() {
  local d
  for d in "${stops[@]}"; do k scale "deployment/$d" --replicas=1 >/dev/null; done
  for d in "${stops[@]}"; do
    k rollout status "deployment/$d" --timeout=5m >/dev/null || fail "$d didn't come up"
  done
}

stop_services() {
  local d
  for d in "${stops[@]}"; do k scale "deployment/$d" --replicas=0 >/dev/null; done
  for d in "${stops[@]}"; do
    until [ -z "$(k get "deployment/$d" -o 'jsonpath={.status.replicas}' | tr -d 0)" ]; do sleep 1; done
  done
  sleep 3
}

old_as_it_was() { # what
  snapshot sneakers-postgres-0 "$work/old-now.txt"
  diff -q "$work/old-before.txt" "$work/old-now.txt" >/dev/null || {
    diff "$work/old-before.txt" "$work/old-now.txt" | head -20 >&2
    fail "the old cluster changed: $1"
  }
  note "ok: $1: the old cluster holds what it held"
}

# The services take the old cluster back, as they do after the box's revert,
# then let go of it again. They write as they start, so the data is compared
# first and the baseline taken again after.
back_on_old() { # what
  old_as_it_was "$1"
  start_services
  note "ok: $1: the services start on the old cluster"
  stop_services
  snapshot sneakers-postgres-0 "$work/old-before.txt"
}

step "the mover"
(cd "$root" && CGO_ENABLED=0 go build -o "$work/mover" ./test/datamove/mover)
slot="$work/slot"
mkdir -p "$slot/datamove"
cp "$root/build/product/sneakers/product.yaml" "$slot/product.yaml"
cp "$root/build/product/sneakers/datamove/"*.sql "$slot/datamove/"
state="$work/state"
mkdir -p "$state"

step "the old chart, with the services on it"
(cd "$CHARTS" && scripts/build-deps.sh)
base=(-f "$CHARTS/charts/sneakers/examples/values-small-box.yaml" -f "$CHARTS/test/kind/values.yaml" --set hydra.enabled=true "${web[@]}")
helm upgrade --install sneakers "$CHARTS/charts/sneakers" -n "$ns" --create-namespace "${base[@]}" --wait --timeout 15m
k rollout status statefulset/sneakers-postgres --timeout=5m
# Everything that connects to the database stops for the move: every
# Deployment but the cache.
mapfile -t stops < <(k get deployments -o name | sed 's|.*/||' | grep -v valkey)
stop="$(IFS=,; echo "${stops[*]}")"

step "seed"
for db in "${databases[@]}"; do
  owner="$(psql_in sneakers-postgres-0 postgres <<<"SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = '$db';")"
  { echo "SET ROLE $owner;"; echo "\\set rows $rows"; cat "$here/seed.sql"; } | psql_in sneakers-postgres-0 "$db"
done
{ echo "SET rehearsal.records = $audit_rows;"; cat "$here/audit-seed.sql"; } | psql_in sneakers-postgres-0 sneakers_audit
psql_in sneakers-postgres-0 postgres <<'SQL'
SELECT 'seeded', datname, pg_size_pretty(pg_database_size(datname)) FROM pg_database WHERE datname LIKE 'sneakers\_%' ORDER BY 2;
SQL

step "the audit chain as seeded"
got="$(psql_in sneakers-postgres-0 sneakers_audit < "$slot/datamove/audit-chain.sql")"
[ "$got" = ok ] || fail "the seeded chain doesn't pass its check: $got"

step "the new cluster, beside the old one"
"$work/mover" cert --slot "$slot" --secret sneakers-pgha-tls --state "$state" | k apply -f -
k patch secret sneakers-bundled --type merge -p "{\"stringData\":{\"replication-password\":\"$(head -c 24 /dev/urandom | base64 | tr -dc a-zA-Z0-9)\",\"rewind-password\":\"$(head -c 24 /dev/urandom | base64 | tr -dc a-zA-Z0-9)\"}}"
pgha=(-f "$root/build/product/sneakers/values-postgres-ha.yaml" --set postgres-ha.storage.size=2Gi)
services_before="$(k get deployments -o jsonpath='{range .items[*]}{.metadata.name}={.metadata.generation} {end}')"
helm upgrade sneakers "$CHARTS/charts/sneakers" -n "$ns" "${base[@]}" "${pgha[@]}" --wait --timeout 5m
k rollout status statefulset/sneakers-pgha --timeout=5m
# It joins the release without touching what's running.
[ "$(k get deployments -o jsonpath='{range .items[*]}{.metadata.name}={.metadata.generation} {end}')" = "$services_before" ] ||
  fail "turning the new cluster on changed a service"
[ "$(k get statefulset sneakers-postgres -o jsonpath='{.status.currentRevision}')" = "$(k get statefulset sneakers-postgres -o jsonpath='{.status.updateRevision}')" ] ||
  fail "turning the new cluster on rolled the old one"
note "ok: the new cluster joined the release, and no service or the old cluster changed"
[ "$(psql_in sneakers-pgha-0 postgres <<<"SHOW ssl;")" = on ] || fail "the new cluster doesn't serve TLS"
got="$(psql_in sneakers-pgha-0 postgres <<<"SELECT datcollate FROM pg_database WHERE datname = 'postgres';")"
[ "$got" = en_US.UTF-8 ] || fail "the new cluster's locale is $got"
got="$(k get statefulset sneakers-pgha -o jsonpath='{.spec.template.spec.containers[0].image}')"
want="$(k get statefulset sneakers-postgres -o jsonpath='{.spec.template.spec.containers[0].image}')"
[ "$got" = "$want" ] || fail "the clusters run different images: $got, $want"
k get pvc data-sneakers-pgha-0 -o name >/dev/null || fail "the new cluster has no volume of its own"
note "ok: sneakers-pgha is up: TLS on, en_US, the old cluster's image, its own volume"

step "stop the services"
stop_services
snapshot sneakers-postgres-0 "$work/old-before.txt"
note "ok: the baseline: $(grep -c '^tbl' "$work/old-before.txt") tables"

for point in mid-dump mid-restore before-switch; do
  step "killed $point"
  set +e
  "$work/mover" move --slot "$slot" --dir "$state" --stop "$stop" --die-at "$point"
  rc=$?
  set -e
  [ "$rc" -eq 137 ] || fail "$point: the mover ended with $rc, not the kill"
  jq -r '"journal: \(.state) at \(.step)"' "$state/data-move.json" | tee -a "$results"
  # The next start finds it cut off and fails it; the box goes back.
  if "$work/mover" move --slot "$slot" --dir "$state" --stop "$stop" 2>"$work/err"; then fail "$point: a cut-off move ran on"; fi
  grep -q 'cut off' "$work/err" || fail "$point: $(cat "$work/err")"
  back_on_old "$point"
done

step "the move"
"$work/mover" move --slot "$slot" --dir "$state" --stop "$stop" | tee "$work/move.log"
[ "$(jq -r .state "$state/data-move.json")" = switched ] || fail "the journal says $(jq -r .state "$state/data-move.json")"
old_as_it_was "the finished move"
snapshot sneakers-pgha-0 "$work/new.txt"
if ! diff "$work/old-before.txt" "$work/new.txt" > "$work/compare.diff"; then
  head -40 "$work/compare.diff" >&2
  fail "the new cluster doesn't hold what the old one did"
fi
note "ok: every table, sequence and object matches: $(grep -c '^tbl' "$work/new.txt") tables, $(grep -c '^obj' "$work/new.txt") objects"
got="$(psql_in sneakers-pgha-0 sneakers_audit < "$slot/datamove/audit-chain.sql")"
[ "$got" = ok ] || fail "the chain on the new cluster: $got"
note "ok: the audit chain holds on the new cluster"

step "the services, on the new cluster"
# One release now, so the upgrade that moves the services goes over the cluster
# they move to. It has to leave it running and leave its Lease with its holder.
pgha_pod="$(k get pod sneakers-pgha-0 -o jsonpath='{.metadata.uid}')"
pgha_lease="$(k get lease sneakers-pgha -o jsonpath='{.spec.holderIdentity}')"
[ -n "$pgha_lease" ] || fail "the new cluster's Lease has no holder"
helm upgrade sneakers "$CHARTS/charts/sneakers" -n "$ns" "${base[@]}" "${pgha[@]}" \
  --set global.database.host=sneakers-pgha-primary --set global.database.sslmode=require
[ "$(k get pod sneakers-pgha-0 -o jsonpath='{.metadata.uid}')" = "$pgha_pod" ] || fail "the upgrade restarted the new cluster"
[ "$(k get lease sneakers-pgha -o jsonpath='{.spec.holderIdentity}')" = "$pgha_lease" ] || fail "the upgrade took the Lease from its holder"
note "ok: an upgrade of the release leaves the new cluster running, and its Lease held"
start_services
"$work/mover" move --slot "$slot" --dir "$state" --settle
[ "$(jq -r .state "$state/data-move.json")" = "done" ] || fail "the move didn't settle"
sleep 5
conns="$(psql_in sneakers-pgha-0 postgres <<'SQL'
SELECT count(*) FILTER (WHERE s.ssl), count(*) FILTER (WHERE NOT s.ssl)
  FROM pg_stat_activity a JOIN pg_stat_ssl s USING (pid) WHERE a.usename = 'sneakers';
SQL
)"
[ "${conns%%|*}" -gt 0 ] && [ "${conns##*|}" = 0 ] || fail "connections with and without TLS: $conns"
note "ok: the services run on the new cluster over TLS: $conns (with|without)"
gw="$(k get pod -l app.kubernetes.io/component=gateway -o jsonpath='{.items[0].metadata.name}')"
got="$(k logs "$gw" --tail=200 | grep -ci 'password authentication failed' || true)"
[ "$got" = 0 ] || fail "logins failed"
old_as_it_was "the services running on the new cluster"

step "only the listed pods reach it"
k run pgha-probe --restart=Never --image="$want" --labels=app=stranger --command -- sh -c 'pg_isready -h sneakers-pgha-primary -t 5' >/dev/null
k wait --for=jsonpath='{.status.phase}'=Failed pod/pgha-probe --timeout=60s >/dev/null || { k get pod pgha-probe -o wide; fail "a pod off the list reached the database"; }
k delete pod pgha-probe --now >/dev/null
note "ok: a pod off the list doesn't reach the new cluster"

step "done"
cat "$results"
