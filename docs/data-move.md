# The data move

A product can move its databases to a new PostgreSQL cluster once, as one step of an upgrade. The
box dumps the old cluster to the backup partition, restores into the new one, proves the copy and
only then lets the services start. It never writes to the old cluster: that cluster and its volume
are the way back, and any failure returns the box to them.

The new cluster gets its own name, on its own volume, because taking over the old volume damages
the way back: the old chart would come back read-only until the new cluster's files were removed by
hand.

The appliance names no chart and no product. The product declares the whole move in its
`product.yaml` ([release.md](release.md#productyaml)):

```yaml
data_move:
  label: Moving the database      # the step's words in Updates and the console
  after: data                     # the phase holding both clusters
  databases: [app_one, app_two]   # moved with the old cluster's roles
  source:
    namespace: app
    name: old-db                  # a StatefulSet; the tools run in old-db-0
    host: 127.0.0.1
    user: postgres
    password_env: POSTGRES_PASSWORD
  target:
    namespace: app
    name: new-db
    host: new-db-primary.app.svc  # what the tools connect to, from inside new-db-0
    port: 5432                    # 5432 without it
    sslmode: require              # disable without it
    ssl_root_cert: /tls/ca.crt    # for verify-ca and verify-full
    user: postgres
    password_env: POSTGRES_PASSWORD
  checks:
    - name: the audit chain
      database: app_one
      file: datamove/audit-chain.sql   # in the bundle
  timeout: 6h                     # from 1m to 24h; 6 hours without it
```

The box refuses a move whose `after` isn't a phase with later phases, a cluster that isn't a
workload of that phase, a target with the source's name, a host or sslmode that libpq can't take, a
`password_env` that isn't a variable's name, a check on a database the move doesn't carry, and a
timeout out of range. `user` is a superuser on both sides.

## What it does

The step `data_move` comes right after the phase `after`, so the later phases aren't placed until
the move is through; on an upgrade the quiesce has already stopped the old version's services.

1. **Prepare.** The old cluster answers, the bundle holds every check, and the move fits
   ([room](#room)). A refusal here leaves everything as it was. An old cluster whose databases hold
   no tables, as on a new box, has nothing to move: the step ends and the product goes on.
2. **Stop.** Anything still running in a later phase is scaled to 0 and its pods have gone.
3. **Dump.** The roles (`pg_dumpall --roles-only`) and each database (`pg_dump --format=custom`)
   go to `/var/lib/sneakers/backup/data-move/dump`, each with its SHA-256, and every table's row
   count is taken. The directory holds only the latest attempt.
4. **Target.** The new cluster answers over the declared host and TLS mode. A target that can't
   do that TLS mode fails here. A target that holds tables this move didn't put there is refused and
   left alone: a move only ever clears what an earlier attempt of its own wrote.
5. **Restore.** Every file is read back and compared with its checksum. The roles go in, leaving any
   role the target already has as it is, passwords included, because the new cluster connects with
   those. Each database is restored with `pg_restore --create`, which brings its owner, locale and
   grants, and every table's row count is compared with the dump, in both directions.
6. **Check.** Each of the product's checks runs on the target.
7. **Start.** The journal says the box has switched, and the phase loop goes on to the next phase.
8. **Settle.** Once the product is ready the move is done for good. Until then a failure of the
   product goes back as well.

The dump's roles file holds password verifiers, so the directory is root's alone, on the encrypted
partition. No password reaches the box's memory, a command line or a log: the tools read it from
the pod's own environment.

## When it fails

Every failure ends the same way. The journal says failed, the step fails with `DATA_MOVE` and says
at which part and why, the box state says failed, and the box reverts to the previous product slot
by itself (`upgrade.data-move-revert` in the audit log, a `revert` line in the history). The old
pins bring the old cluster and its volume back as they were. The services never ran on the target,
unless the failure came from a later phase of the same apply.

The next apply starts from the top and clears what the failed attempt left in the target.

The journal is `/var/lib/sneakers/platform/data-move.json`, written and synced before each step, so
a power loss can't lose it. A move found running at the next start was cut off: it counts as failed
and the box goes back, whatever it had got to. What a tool says goes through a scrub first, since
an error can quote a row; only the first error line reaches the logs and the step, cut before
anything that quotes.

With no previous slot, or with an elevated shell open, the revert can't run: the box stays failed,
and the old cluster is untouched. An owner reverts by hand, or the next start tries the move again.

A revert an admin asks for after the move has settled goes back to the old cluster as it stood at
the move. What was written on the new cluster since stays there and isn't carried back, and applying
again doesn't move anything a second time.

`sneakers reset` removes the journal with the data.

## Room

The old volume, the dump and the new volume exist at once, about 2.3 times the data, so the step
refuses to start if they won't fit, with `DATA_MOVE_ROOM`, before anything stops. It reads the real
size of the databases, and asks for 35% of that for the dump on the backup partition, plus the data
and 1 GiB of write-ahead log on the data volume. Measured dumps came to 30%. When both are on one
filesystem they count together. The refusal says how much it needs and where.

## How long it takes

The product is offline for the whole move, once on a box. The step isn't held to the product's
`ready.timeout`, and the phases after it get all of theirs. Only the move's own `timeout` bounds it,
as a guard against one that hangs. The step's detail says what it's doing ("Restoring app_one
(2 of 6)").

## A product's check

A check is a query in the bundle. It runs as a superuser on the target before any service has
started, so it can't ask a service, and prints exactly `ok` when the data is sound. Anything else
fails the move and is shown, so it must print only what's safe to log: a sequence number, not a row.

`build/product/sneakers/datamove/audit-chain.sql` walks the audit trail's hash chain, the same check
VerifyChain makes in sneakers-audit. A change to how that service hashes a record has to change this
file too; the test in `internal/datamove` carries a copy of the canonical form to catch it.

## Testing it

The unit tests run with fakes behind the package's own interfaces. The real ones need docker and
nothing else, and run the real tools against plain PostgreSQL containers:

```sh
go test -tags integration ./internal/datamove/
```

They move six databases and compare every row, and check TLS and password logins over the network.
They kill `pg_dump` and `pg_restore` with SIGKILL mid-stream, lose the target just before the
switch, and SIGKILL the moving process itself at each of those points, as a power loss would. Each
time the old cluster must hold exactly what it held and still take writes, and the next attempt must
succeed. `DATAMOVE_POSTGRES_IMAGE` picks the image.
