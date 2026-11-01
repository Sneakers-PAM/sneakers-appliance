#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# new-box.sh: the data move on a box with nothing to move. Both clusters come
# up empty, the move ends without stopping or restoring anything, and the
# services make their tables on the new cluster over TLS. It takes the
# environment rehearsal.sh does, and runs after it on the same kind cluster:
# it replaces the namespace.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${CHARTS:?CHARTS is a sneakers-release checkout}"
work="${WORK_DIR:-$(mktemp -d)}/new-box"
mkdir -p "$work/slot/datamove" "$work/state"
ns=sneakers
fail() { echo "FAIL: $*" >&2; exit 1; }
ctx="$(kubectl config current-context)"
case "$ctx" in kind-*) ;; *) fail "the context $ctx isn't a kind cluster" ;; esac
k() { kubectl -n "$ns" "$@"; }
web=()
if [ "${SKIP_WEB:-}" = 1 ]; then web=(--set web-staff.enabled=false --set web-admin.enabled=false); fi

helm -n "$ns" uninstall sneakers-pgha sneakers --wait 2>/dev/null || true
kubectl delete namespace "$ns" --wait --ignore-not-found

(cd "$root" && CGO_ENABLED=0 go build -o "$work/mover" ./test/datamove/mover)
cp "$root/build/product/sneakers/product.yaml" "$work/slot/product.yaml"
cp "$root/build/product/sneakers/datamove/"*.sql "$work/slot/datamove/"

helm upgrade --install sneakers "$CHARTS/charts/sneakers" -n "$ns" --create-namespace \
  -f "$CHARTS/charts/sneakers/examples/values-small-box.yaml" -f "$CHARTS/test/kind/values.yaml" "${web[@]}" \
  --set global.database.host=sneakers-pgha-primary --set global.database.sslmode=require --no-hooks
chart="$(HELM="${HELM:-helm}" bash "$CHARTS/scripts/pull-postgres-ha.sh" "$work/pgha")"
"$work/mover" cert --slot "$work/slot" --secret sneakers-pgha-tls --state "$work/state" | k apply -f -
pw() { head -c 24 /dev/urandom | base64 | tr -dc a-zA-Z0-9; }
k patch secret sneakers-bundled --type merge -p "{\"stringData\":{\"replication-password\":\"$(pw)\",\"rewind-password\":\"$(pw)\"}}"
helm upgrade --install sneakers-pgha "$chart" -n "$ns" \
  -f "$CHARTS/deploy/postgres-ha/values.yaml" -f "$CHARTS/deploy/postgres-ha/values-small-box.yaml" \
  -f "$root/build/product/sneakers/values-postgres-ha.yaml" --set storage.size=1Gi --wait --timeout 5m

"$work/mover" move --slot "$work/slot" --dir "$work/state" --stop ""
[ "$(jq -r '.state + " " + (.nothing | tostring)' "$work/state/data-move.json")" = "done true" ] ||
  fail "the journal says $(cat "$work/state/data-move.json")"
# Kratos and Hydra's migrations are hooks, skipped above while the database
# wasn't there; a plain upgrade runs them.
helm upgrade sneakers "$CHARTS/charts/sneakers" -n "$ns" \
  -f "$CHARTS/charts/sneakers/examples/values-small-box.yaml" -f "$CHARTS/test/kind/values.yaml" "${web[@]}" \
  --set global.database.host=sneakers-pgha-primary --set global.database.sslmode=require --wait --timeout 10m
tables="$(k exec -i sneakers-pgha-0 -c postgres -- psql -U postgres -d sneakers_audit -qtAX -c "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")"
[ "$tables" -gt 0 ] || fail "the audit service made no tables on the new cluster"
none="$(k exec -i sneakers-postgres-0 -- psql -U postgres -d sneakers_audit -qtAX -c "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")"
[ "$none" = 0 ] || fail "the old cluster has $none tables"
echo "ok: a new box has nothing to move, and the services start on the new cluster"
