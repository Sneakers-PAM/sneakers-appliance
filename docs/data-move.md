# The data move

A product can move its databases to a new PostgreSQL cluster as one step of an upgrade: once, unless
a [revert](#going-back-and-returning) goes back over it. The box dumps the old cluster to the backup partition, restores into the new one, proves the copy and
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
    host: new-db-primary.app.svc  # what the tools connect to, from inside new-db-0, or the
                                  # directory of its local socket
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
timeout out of range. `user` is a superuser on both sides. A `host` that's a socket directory takes
no `sslmode`, since libpq ignores it there, and needs no `password_env` when the pod's own user is a
superuser: Sneakers' target logs in that way, because that chart keeps its passwords in files. Its
services then prove TLS as they start, and a failure there goes back like any other.

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
8. **Settle.** Once the product is ready the move is done, and the working dump is removed. Until
   then a failure of the product goes back as well.

The dump's roles file holds password verifiers, so the directory is root's alone, on the encrypted
partition, and it goes as soon as it's worthless: at the settle, or after a failed attempt once the
box is back on the old cluster. A removal that fails never fails the box: it's logged, the journal
says so in `dump_left`, and the next start tries again. No password reaches the box's memory, a command line or a log: the tools read it from
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

`sneakers reset` removes the journal, the working dump and every kept dump with the data.

## Going back and returning

Any slot switch that lands on a slot without the target's workload goes back over the move: Revert on
Updates, the revert of a later failure, or an apply of an older bundle. The box judges that by the
slot itself, right after the switch and again at every start, so a switch cut off in between is still
caught. A failed move isn't one of these: the services never settled on its target.

The journal says `reverted`, and the switch says what that means in the Updates step, the history
line and `upgrade.data-move-reverted` in the audit log: the box is back on the old cluster as it stood
at the move, and what was written on the new cluster since stays there and isn't carried back.

The services now write to the old cluster, so that's the data the box has to return with. A recorded
revert is what triggers it, because row counts miss updates and LSNs move on a restart. The next time
the step runs (an apply, a reinstall, or a revert back to the moving slot), it does this before its
usual steps, with the step's detail saying so (`upgrade.data-move-return` in the audit log):

1. **Check.** The new cluster has to answer, and the [room](#room) has to fit the kept dump too. A
   refusal here touches nothing.
2. **Keep.** After the usual stop and dump, and only once the foreign-target guard has passed, every
   moved database that holds tables is dumped to
   `/var/lib/sneakers/backup/data-move/replaced-<UTC stamp>/`, with the roles, checksums and row counts
   a normal dump has, and every file is read back and compared. Until that's on disk and in the journal
   the target isn't touched: a failure or a power loss here ends like any other failure, with the
   target as it was. The next attempt removes the unfinished dump and starts over.
3. **Move.** The target is cleared and restored from the old cluster as usual. An attempt cut off here
   leaves the target part way, so the next attempt never keeps it again: the journal's `kept` names
   the dump that holds the real data.

Both sides' writes exist afterwards: the old side's are live, the new side's are in the dump, and
`upgrade.data-move-kept` says where. The target's volume is a host path that outlives the old pins,
so the target usually comes back with its data. If the volume is gone the target is empty: there's
nothing to keep, and the audit entry says `nothing`. Only a target this move's journal says it filled
may be replaced; any other is still refused and left alone.

A later revert and return repeat all of this and add another dump.

While a return is owed, from the revert until the box has moved again, an apply looks at the staged
bundle before anything changes. A bundle that declares `data_move` goes ahead and returns. So does one
without it that still has the old cluster, in its phases or its stacks, such as an older bundle: the
box stays on that cluster. A bundle with neither would start on the new cluster with no move and
strand what was written on the old one, so it's refused with `DATA_MOVE_BUNDLE`, the product keeps
running and the bundle stays staged. That holds for a failed return too, and for an update window's
apply.

A move that found nothing to move never filled the target, so its journal can't vouch for what the
services later wrote there. If the old cluster then holds tables too, the return is refused as a
foreign target, and nothing is lost.

## Kept dumps

The box never removes a kept dump itself, because that would be a silent loss. They stay until an
owner removes them or `sneakers reset` runs, and they count against the room of the next return.

```sh
sneakers dumps list
sneakers dumps remove replaced-20261101T120000Z
```

`dumps remove` is an owner's, over SSH, with the name typed again and a new authenticator code, and is
audited as `product.kept-dump.remove`. Until the box has settled on the new cluster, the dump of that
return is refused with `DATA_MOVE_DUMP`, since it's the only copy of what it holds.

To read one, restore a database next to the live data from the root shell, with `new-db` the target's
name, and drop it when you're done:

```sh
cd /var/lib/sneakers/backup/data-move/replaced-20261101T120000Z
k0s kubectl exec -i -n app new-db-0 -- sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" psql -h 127.0.0.1 -U postgres -d postgres -c "CREATE DATABASE kept_app_one"'
k0s kubectl exec -i -n app new-db-0 -- sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" pg_restore -h 127.0.0.1 -U postgres --no-owner --dbname=kept_app_one' < app_one.dump
```

`manifest.json` lists each file's SHA-256 and every table's row count, and `roles.sql` holds the roles
with their password verifiers.

## Room

The old volume, the dump and the new volume exist at once, about 2.3 times the data, so the step
refuses to start if they won't fit, with `DATA_MOVE_ROOM`, before anything stops. It reads the real
size of the databases, and asks for 35% of that for the dump on the backup partition, plus the data
and 1 GiB of write-ahead log on the data volume. Measured dumps came to 30%. When both are on one
filesystem they count together. The refusal says how much it needs and where.

A return also needs 35% of the target's databases for the kept dump, when there's one to write. The
target's own files go as each database is replaced, so the data volume needs only what the restore
grows past that at its fullest, plus the 1 GiB of write-ahead log. Kept dumps from earlier returns
stay where they are and take their room: a return that won't fit is refused with `DATA_MOVE_ROOM`
rather than dropping one, and [`dumps remove`](#kept-dumps) is how an owner makes room.

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
succeed. They then go through a settle, a revert, a write on each side and a return: the old side's
write is live, the new side's restores from the kept dump, and that holds with no room, with the
kept dump or the second restore killed, and with the box dying in either. `DATAMOVE_POSTGRES_IMAGE`
picks the image.

The rehearsal does the same against the real charts on a kind cluster, with the real services and
the Secrets as a box makes them. `test/datamove/rehearsal.sh` seeds the old cluster, brings up the
new one beside it with the bundle's values, and SIGKILLs the real move mid-dump, mid-restore and
just before the switch. Each time the old cluster must hold what it held and the services must
start on it. The last run goes through, every table's rows, every sequence and object, the locale,
the owners and the audit chain are compared, and the services start on the new cluster over TLS.
It takes a sneakers-release checkout with its service images loaded:

```sh
CHARTS=../sneakers-release bash test/datamove/rehearsal.sh
```

`SKIP_WEB=1` leaves out the two web apps, and `SEED_ROWS` and `AUDIT_ROWS` size the data.
`test/datamove/new-box.sh` runs after it on the same cluster and takes the same settings: both
clusters come up empty, nothing moves, and the services make their tables on the new one. The
`Data Move Rehearsal` workflow runs it on amd64 and arm64. The real-bundle job's `move` leg
([testing.md](testing.md#the-real-bundle-job)) takes a box from rc.6 through the normal update path
in QEMU.
