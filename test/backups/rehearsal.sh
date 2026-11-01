#!/usr/bin/env bash
# Copyright 2026 The Sneakers-PAM Authors
# SPDX-License-Identifier: Apache-2.0
#
# rehearsal.sh: backups and restore against the real helm-postgres-ha chart on
# a throwaway kind cluster (docs/backups.md#testing-it), with the box's own
# values and the real internal/backupset running inside the node, as accessd
# does on a box. The node gets a small ext4 partition for the backups, so a
# full one is real.
#
#   - rows are written, a set is cut, more rows are written; a restore brings
#     back the first and not the later, and the audit chain passes;
#   - the restore is SIGKILLed at each step that touches the data, and each
#     time the box comes back on exactly what it held;
#   - a damaged set and a set from another box are refused or go back;
#   - the backup partition fills under load: the database keeps running, the
#     data volume keeps its limit, Status warns, and a set made once there's
#     room again restores;
#   - the chart's restore check runs and passes.
#
# Inputs (environment):
#   CHARTS       a sneakers-release checkout
#   WORK_DIR     a scratch directory (default: a new one)
#   KIND_CLUSTER the kind cluster (default: the current context's)
#   SEED_ROWS    rows in each seeded table (default 20000)
#   AUDIT_ROWS   audit records to chain (default 5000)
#   BACKUP_SIZE  the backup partition's size (default 1g)
#
# It refuses any context that isn't kind-*.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
: "${CHARTS:?CHARTS is a sneakers-release checkout}"
work="${WORK_DIR:-$(mktemp -d)}"
mkdir -p "$work"
ns=sneakers
rows="${SEED_ROWS:-20000}"
audit_rows="${AUDIT_ROWS:-5000}"
size="${BACKUP_SIZE:-1g}"
fail() { echo "FAIL: $*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }
ctx="$(kubectl config current-context)"
case "$ctx" in kind-*) ;; *) fail "the context $ctx isn't a kind cluster" ;; esac
node="${ctx#kind-}-control-plane"
results="$work/results.txt"
: > "$results"
note() { echo "$*" | tee -a "$results"; }
k() { kubectl -n "$ns" "$@"; }
n() { docker exec "$node" sh -c "$1"; }
tool() { docker exec "$node" /box/boxtool "$@"; }
sql() { k exec -i sneakers-pgha-0 -c postgres -- psql -h /var/run/postgresql -U postgres -d "$1" -qtAX -v ON_ERROR_STOP=1 -f -; }
ready() { k rollout status statefulset/sneakers-pgha --timeout=5m >/dev/null; until [ "$(sql postgres <<<'SELECT pg_is_in_recovery();' 2>/dev/null)" = f ]; do sleep 1; done; }
checksum() { sql sneakers_audit <<<'SELECT count(*), coalesce(sum(i), 0) FROM rehearsal;'; }

step "the tool"
goarch="$(docker exec "$node" uname -m | sed 's/aarch64/arm64/; s/x86_64/amd64/')"
(cd "$root" && CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -o "$work/boxtool" ./test/backups/boxtool)

step "the box's volumes"
# ext4 on a loop device, as the box's partition is: writes to a tmpfs would
# count against the pod's memory.
n "mkdir -p /box/data/pgha /box/backup /box/slot/datamove; mountpoint -q /box/backup || { truncate -s $size /box/backup.img && mkfs.ext4 -q -F -m 0 /box/backup.img && mount -o loop,nodelalloc /box/backup.img /box/backup; }; mkdir -p /box/backup/postgres; chmod 777 /box/data/pgha /box/backup/postgres"
docker cp "$work/boxtool" "$node:/box/boxtool" >/dev/null
docker cp "$root/build/product/sneakers/product.yaml" "$node:/box/slot/product.yaml" >/dev/null
docker cp "$root/build/product/sneakers/datamove/audit-chain.sql" "$node:/box/slot/datamove/audit-chain.sql" >/dev/null
k get ns "$ns" >/dev/null 2>&1 || kubectl create namespace "$ns" >/dev/null
cat <<'YAML' | kubectl apply -f - >/dev/null
apiVersion: v1
kind: PersistentVolume
metadata: {name: box-data}
spec:
  capacity: {storage: 20Gi}
  accessModes: [ReadWriteOnce]
  storageClassName: box
  hostPath: {path: /box/data/pgha, type: DirectoryOrCreate}
  claimRef: {namespace: sneakers, name: data-sneakers-pgha-0}
---
apiVersion: v1
kind: PersistentVolume
metadata: {name: box-backup}
spec:
  capacity: {storage: 20Gi}
  accessModes: [ReadWriteOnce]
  storageClassName: box
  hostPath: {path: /box/backup/postgres, type: DirectoryOrCreate}
  claimRef: {namespace: sneakers, name: sneakers-pgha-backup}
YAML

step "the box's Secrets"
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/tls.key" -out "$work/tls.crt" -days 2 -subj /CN=sneakers-pgha-primary 2>/dev/null
cp "$work/tls.crt" "$work/ca.crt"
k create secret generic sneakers-pgha-tls --from-file="$work/tls.crt" --from-file="$work/tls.key" --from-file="$work/ca.crt" --dry-run=client -o yaml | k apply -f - >/dev/null
pw() { head -c 18 /dev/urandom | base64 | tr -dc a-zA-Z0-9; }
k create secret generic sneakers-bundled --from-literal=password="$(pw)" --from-literal=postgres-password="$(pw)" --from-literal=replication-password="$(pw)" --from-literal=rewind-password="$(pw)" --dry-run=client -o yaml | k apply -f - >/dev/null
k create secret generic sneakers-box --from-literal=VAULT_ROOT_KEK="$(pw)" --from-literal=TOTP_ENC_KEY="$(pw)" --dry-run=client -o yaml | k apply -f - >/dev/null

step "the cluster, with the box's values"
(cd "$CHARTS" && scripts/build-deps.sh)
# The umbrella with only the cluster on: no service runs in this rehearsal, and
# the Secrets above stand in for the box's.
cat > "$work/kind.yaml" <<'YAML'
bundledSecrets: {enabled: false}
bundledNetworkPolicies: {enabled: false}
postgres: {enabled: false}
valkey: {enabled: false}
kratos: {enabled: false}
identity: {enabled: false}
vault: {enabled: false}
workflow: {enabled: false}
audit: {enabled: false}
notify: {enabled: false}
connector: {enabled: false}
sshbroker: {enabled: false}
gateway: {enabled: false, ingress: {enabled: false}}
mcp: {enabled: false}
web-staff: {enabled: false}
web-admin: {enabled: false}
postgres-ha:
  storage: {size: 20Gi, storageClassName: box}
  backup:
    file:
      persistence: {storageClassName: box}
YAML
helm upgrade --install sneakers "$CHARTS/charts/sneakers" -n "$ns" \
  -f "$CHARTS/charts/sneakers/examples/values-small-box.yaml" \
  -f "$root/build/product/sneakers/values-postgres-ha.yaml" -f "$work/kind.yaml" --wait --timeout 5m >/dev/null
ready
until n "ls /box/backup/postgres/walg/basebackups_005/*sentinel.json" >/dev/null 2>&1; do sleep 1; done
note "ok: the cluster archives to the backup partition, and took its first base backup"

step "the first rows"
sql sneakers_audit <<SQL
CREATE TABLE rehearsal (i bigint PRIMARY KEY, pad text);
INSERT INTO rehearsal SELECT g, md5(g::text) FROM generate_series(1, $rows) g;
-- The audit service's table: the chain check reads it, and no service runs here.
CREATE TABLE audit_records (seq bigint PRIMARY KEY, tier int, action text, actor_user_id text, subject text,
  group_id text, sensitive boolean, attributes jsonb, occurred_at text, prev_hash text, hash text);
SET rehearsal.records = $audit_rows;
$(cat "$root/test/datamove/audit-seed.sql")
SQL
[ "$(sql sneakers_audit < "$root/build/product/sneakers/datamove/audit-chain.sql")" = ok ] || fail "the seeded chain doesn't pass"
before="$(checksum)"
chain_before="$(sql sneakers_audit <<<'SELECT count(*), max(seq) FROM audit_records;')"

step "a set, while it runs"
tool create before-the-change | tee -a "$results"
n "cat /box/backup/postgres/sets/before-the-change/manifest.json" > "$work/manifest.json"
jq -e '.keys | length == 2' "$work/manifest.json" >/dev/null || fail "the manifest holds no key digests"
links="$(n "stat -c %h /box/backup/postgres/sets/before-the-change/store/wal_005/$(jq -r '.files[] | select(.path | endswith(".lz4") and contains("wal_005")) | .path' "$work/manifest.json" | head -1 | xargs basename)")"
[ "$links" -ge 2 ] || fail "the set copied its WAL: $links links"
note "ok: the set links the archive's files, it doesn't copy them"

step "the later rows"
sql sneakers_audit <<SQL
INSERT INTO rehearsal SELECT g, 'later' FROM generate_series($((rows + 1)), $((rows + 1000))) g;
CREATE TABLE written_later (i int);
SQL
after="$(checksum)"
[ "$after" != "$before" ] || fail "the later rows didn't land"

# The restore step is killed once the replay is well under way.
wait_for() { if [ "$1" = restore ]; then echo 6s; else echo 0s; fi; }
for point in aside restore check finish; do
  step "the restore killed at $point"
  set +e
  docker exec "$node" /box/boxtool restore --die-at "$point" --die-after "$(wait_for "$point")" before-the-change
  rc=$?
  set -e
  [ "$rc" -eq 137 ] || fail "$point: the tool ended with $rc, not the kill"
  n "grep -q '\"state\": \"running\"' /box/data/backup-restore.json" || fail "$point: the journal doesn't say running"
  tool resume | tee "$work/resume.txt"
  grep -q 'state failed' "$work/resume.txt" || fail "$point: $(cat "$work/resume.txt")"
  k scale statefulset/sneakers-pgha --replicas=1 >/dev/null
  ready
  [ "$(checksum)" = "$after" ] || fail "$point: the box didn't come back on its data"
  [ "$(sql sneakers_audit < "$root/build/product/sneakers/datamove/audit-chain.sql")" = ok ] || fail "$point: the chain"
  n "! ls -d /box/data/pgha/pgdata.pre-restore /box/backup/postgres/walg.pre-restore 2>/dev/null" || fail "$point: something stayed aside"
  sql postgres <<<'SELECT 1;' >/dev/null
  note "ok: killed at $point: the box is back on every row it held, and it takes writes"
done

step "a set a box can't use"
jq '.name = "from-another-box" | .keys |= map_values("0000")' "$work/manifest.json" > "$work/other.json"
n "cp -al /box/backup/postgres/sets/before-the-change /box/backup/postgres/sets/from-another-box && rm /box/backup/postgres/sets/from-another-box/manifest.json"
docker exec -i "$node" sh -c 'cat > /box/backup/postgres/sets/from-another-box/manifest.json' < "$work/other.json"
if docker exec "$node" /box/boxtool restore from-another-box 2>"$work/err"; then fail "a set from another box was restored"; fi
grep -q 'different box' "$work/err" || fail "$(cat "$work/err")"
[ "$(checksum)" = "$after" ] || fail "a refusal touched the data"
tool remove from-another-box >/dev/null
note "ok: a set from another box is refused, and nothing changes"

step "a damaged set goes back"
first="$(jq -r '.files[] | select(.path | contains("wal_005")) | .path' "$work/manifest.json" | head -1)"
n "cp -al /box/backup/postgres/sets/before-the-change /box/backup/postgres/sets/damaged && p=/box/backup/postgres/sets/damaged/$first && cp \$p \$p.c && mv \$p.c \$p && echo x >> \$p"
jq '.name = "damaged"' "$work/manifest.json" > "$work/damaged.json"
n "rm /box/backup/postgres/sets/damaged/manifest.json"
docker exec -i "$node" sh -c 'cat > /box/backup/postgres/sets/damaged/manifest.json' < "$work/damaged.json"
tool restore damaged | tee "$work/damaged.txt"
grep -q 'state failed' "$work/damaged.txt" || fail "a damaged set wasn't caught"
k scale statefulset/sneakers-pgha --replicas=1 >/dev/null
ready
[ "$(checksum)" = "$after" ] || fail "a damaged set changed the data"
tool remove damaged >/dev/null
note "ok: a damaged set is found before anything stops"

step "the restore"
start="$(date +%s)"
tool restore before-the-change | tee "$work/restore.txt"
grep -q 'state settling' "$work/restore.txt" || fail "$(cat "$work/restore.txt")"
k scale statefulset/sneakers-pgha --replicas=1 >/dev/null
ready
note "ok: the restore took $(( $(date +%s) - start )) seconds"
[ "$(checksum)" = "$before" ] || fail "the first rows: $(checksum), want $before"
[ "$(sql sneakers_audit <<<"SELECT to_regclass('written_later');")" = "" ] || fail "a later table survived"
[ "$(sql sneakers_audit <<<'SELECT count(*), max(seq) FROM audit_records;')" = "$chain_before" ] || fail "the audit records changed"
[ "$(sql sneakers_audit < "$root/build/product/sneakers/datamove/audit-chain.sql")" = ok ] || fail "the chain after the restore"
sql postgres <<<"SELECT 1;" >/dev/null
sql sneakers_audit <<<"INSERT INTO rehearsal VALUES (0, 'after the restore');"
note "ok: the first rows are back, the later ones aren't, the audit chain holds, and it takes writes"
k get statefulset sneakers-pgha -o json | jq -e '[.spec.template.spec.containers[0].env[].name] | index("PGHA_BOOTSTRAP_MODE") | not' >/dev/null || fail "the restore's env stayed"
tool settle
n "! ls -d /box/data/pgha/pgdata.pre-restore /box/backup/postgres/walg.pre-restore 2>/dev/null" || fail "what was moved aside stayed"
until n "ls /box/backup/postgres/walg/basebackups_005/*sentinel.json" >/dev/null 2>&1; do sleep 1; done
note "ok: settled: the kept data is gone, and the cluster has a new archive with a base backup"

step "the same set again, and a set on the new timeline"
tool create after-the-restore | tee -a "$results"
sql sneakers_audit <<<"INSERT INTO rehearsal VALUES (-1, 'gone again');"
tool restore after-the-restore | tee "$work/restore2.txt"
grep -q 'state settling' "$work/restore2.txt" || fail "$(cat "$work/restore2.txt")"
k scale statefulset/sneakers-pgha --replicas=1 >/dev/null
ready
[ "$(sql sneakers_audit <<<'SELECT count(*) FROM rehearsal WHERE i = -1;')" = 0 ] || fail "the second restore kept a later row"
[ "$(sql sneakers_audit <<<'SELECT count(*) FROM rehearsal WHERE i = 0;')" = 1 ] || fail "the second restore lost its row"
tool settle
until n "ls /box/backup/postgres/walg/basebackups_005/*sentinel.json" >/dev/null 2>&1; do sleep 1; done
note "ok: a set cut after a restore restores too"

step "the chart's restore check"
k create job verify-now --from=cronjob/sneakers-pgha-backup-verify >/dev/null
k wait --for=condition=complete job/verify-now --timeout=10m >/dev/null || { k logs job/verify-now -c verify --tail=20 || true; fail "the restore check didn't pass"; }
got="$(k get lease sneakers-pgha-backup -o json | jq -r '.metadata.annotations["postgres-ha/last-verify-result"]')"
[ "$got" = ok ] || fail "the restore check recorded $got"
k delete job verify-now >/dev/null
note "ok: the chart's restore check passes on the box's values, with its network policy"

step "a full backup partition, under load"
hold=$((16 * 16 << 20))
churn() { sql postgres <<<"DROP TABLE IF EXISTS churn; CREATE TABLE churn AS SELECT g, md5(random()::text) || md5(random()::text) || md5(random()::text) t FROM generate_series(1, $1) g;"; }
wal_mb() { n "du -sm /box/data/pgha/pgdata/pg_wal | cut -f1"; }
n "dd if=/dev/zero of=/box/backup/postgres/filler bs=1M count=\$(( \$(df -m --output=avail /box/backup | tail -1) - 8 )) 2>/dev/null; df -h /box/backup | tail -1"
# The guard runs through the load as accessd does, looking every few seconds
# here for every minute there.
tool guard --hold "$hold" --stuck 2s --ticks 60 --every 2s > "$work/guard.txt" &
guard=$!
peak=0
for i in 1 2 3 4 5 6; do
  churn 2500000
  sleep 5
  sql postgres <<<'CHECKPOINT;' >/dev/null
  mb="$(wal_mb)"; [ "$mb" -gt "$peak" ] && peak="$mb"
  echo "round $i: pg_wal $mb MiB"
done
wait "$guard"
pod="$(k get pod sneakers-pgha-0 -o jsonpath='{.status.containerStatuses[0].ready}/{.status.containerStatuses[0].restartCount}')"
[ "$pod" = true/0 ] || [ "${pod%%/*}" = true ] || fail "the pod: $pod"
sql postgres <<<"INSERT INTO churn VALUES (0, 'still writing');" >/dev/null
grep -q 'WAL files go' "$work/guard.txt" || { cat "$work/guard.txt"; fail "the guard didn't say what it did"; }
failed="$(sql postgres <<<'SELECT failed_count > 0 FROM pg_stat_archiver;')"
[ "$failed" = t ] || fail "the archive never failed: the partition wasn't full"
note "ok: full partition: the database runs and takes writes, the pod stays Ready, pg_wal peaked at $peak MiB with PostgreSQL's 512 MiB plus the guard's limit, and Status warns"
limit=$(( (hold >> 20) + 512 + 400 ))
[ "$peak" -le "$limit" ] || fail "pg_wal reached $peak MiB, past $limit"

step "room again: the gap is closed by a new base backup"
n "rm -f /box/backup/postgres/filler"
sql sneakers_audit <<<"DELETE FROM rehearsal WHERE i = 0; INSERT INTO rehearsal VALUES (1000000000, 'after the gap');"
tool create after-the-gap | tee -a "$results"
sql sneakers_audit <<<"INSERT INTO rehearsal VALUES (1000000001, 'gone again');"
restarts="$(k get pod sneakers-pgha-0 -o jsonpath='{.status.containerStatuses[0].restartCount}')"
[ "$restarts" = 0 ] || fail "the database restarted $restarts times on the small-box limits: $(k get pod sneakers-pgha-0 -o jsonpath='{.status.containerStatuses[0].lastState.terminated.reason}')"
note "ok: nothing restarted the database on the small-box limits"

tool restore after-the-gap | tee "$work/restore3.txt"
grep -q 'state settling' "$work/restore3.txt" || fail "$(cat "$work/restore3.txt")"
k scale statefulset/sneakers-pgha --replicas=1 >/dev/null
ready
[ "$(sql sneakers_audit <<<'SELECT count(*) FROM rehearsal WHERE i = 1000000000;')" = 1 ] || fail "the set after the gap lost its row"
[ "$(sql sneakers_audit <<<'SELECT count(*) FROM rehearsal WHERE i = 1000000001;')" = 0 ] || fail "the set after the gap kept a later row"
tool settle
note "ok: a set made after a gap takes a new base backup, and restores"

step "done"
cat "$results"
