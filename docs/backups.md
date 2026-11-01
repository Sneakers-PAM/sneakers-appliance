# Backups

The product's database archives itself to the box's encrypted backup partition, and the box cuts
**backup sets** from that archive: a base backup and the write-ahead log (WAL) up to a named restore
point. A set restores on the box that made it. Retention settings, scheduled pushes off the box and
tighter compression come later ([#2](https://github.com/Sneakers-PAM/sneakers-appliance/issues/2),
[#462](https://github.com/Sneakers-PAM/sneakers-appliance/issues/462) and
[#6](https://github.com/Sneakers-PAM/sneakers-appliance/issues/6)).

The appliance names no chart and no product. The product declares everything in its `product.yaml`
([release.md](release.md#productyaml)):

```yaml
backups:
  label: Restoring the database     # the step's words in Updates and the console
  after: data                       # the phase holding the cluster
  cluster:                          # as a data move's cluster (data-move.md)
    namespace: app
    name: db
    host: /var/run/postgresql
    user: postgres
  claim: db-backup                  # the render's claim for the backup volume
  dir: postgres                     # its directory on the backup partition
  mount: /backup                    # where the pods see that directory
  store: walg                       # the archive, under dir
  data: database                    # the data path (product.yaml data) of the cluster's volume
  pgdata: pgdata                    # the data directory under it
  databases: [app_audit]            # what the checks may name
  command: [/tools/agent, backup]   # asks the running cluster for a base backup
  status:                           # the Lease annotations holding how backups went
    lease: db-backup
    success: example/last-success
    failure: example/last-failure
    verify: example/last-verify
    verify_result: example/last-verify-result
    verify_ok: ok
  restore:
    env:                            # goes on the StatefulSet for a restore, and comes off after
      MODE: restore
      FROM: "{set}"                 # the set's store as the pod sees it
      TARGET: "{point}"             # the restore point's name
    identity_lease: db              # the Lease tying the cluster to its data
    identity_annotations: [example/system-identifier]
  checks:                           # as a data move's: each prints exactly ok
    - {name: the audit chain, database: app_audit, file: backups/chain.sql}
```

The product also has to declare `escrow`: a set is tied to the box by those keys.

## What runs on the box

The bundle's render turns the claim into a hostPath on the backup partition,
`/var/lib/sneakers/backup/<dir>`, for the cluster and for the restore check alike
(`build/tools/stack`). Every other claim stays under `/var/lib/sneakers-data`. It's the partition's
own directory, so it stays clear of `data-move/`, and only the cluster's user can read it.

| What | Where | When (UTC) |
|---|---|---|
| WAL archiving | `<dir>/<store>/wal_005` | continuously, and at least every 5 minutes |
| A base backup | `<dir>/<store>/basebackups_005` | Sneakers: nightly at 01:15, and once at the first start |
| The restore check | a throwaway server in a Job, in `emptyDir` scratch | Sneakers: nightly at 03:45 |
| The sets | `<dir>/sets/<name>` | when an admin asks |

For Sneakers the schedules, the seven nightly base backups the chart keeps and the small-box limits
are in sneakers-release's `deploy/postgres-ha/`. On a small box one upload and one disk reader run at
a time, inside the database pod's 512 MiB, and the restore check gets at most 512 MiB and one CPU.
The check runs on the state volume, up to the database's size. Nothing here is a setting yet: that's
[#2](https://github.com/Sneakers-PAM/sneakers-appliance/issues/2).

## Sets

```sh
sneakers backup create before-the-change
sneakers backup list
```

`backup create` is an admin's, over SSH, and the product keeps running:

1. **Base.** With no base backup in the archive, the box asks for one and waits.
2. **Point.** It makes the named restore point (the set's name and the time), closes the WAL segment
   and waits for it to reach the archive, for up to 5 minutes. A point that doesn't get there fails
   with `BACKUP`: the archive is stuck.
3. **Chain.** Every WAL segment from the newest base backup to the point has to be in the archive. If
   one isn't, as after a [gap](#a-full-backup-partition), the box takes a new base backup and a new
   point after it.
4. **Link.** The base backup, those segments and the timeline histories are hard-linked into
   `sets/<name>`, so a set costs no copy and the archive's own retention can't take it. Once the
   archive lets those files go, the set is what holds their space.
5. **Manifest.** `manifest.json` goes in last, with every file's SHA-256, the point, the LSN, the
   timeline and a digest of each product key. A directory without one isn't a set, and the set
   appears in one rename.

`product.backup.create` goes in the audit log.

### Taking one off the box

```sh
ssh owner@box1.sneakers.example.org sneakers backup export before-the-change --code 123456 > before-the-change.age
```

An export is an owner's, with a new authenticator code. It's one tar encrypted with
age to the box's recovery keys, so nothing leaves in the clear, the box
can't read it back and any one recovery key opens it:

```sh
age -d -i ~/.ssh/sneakers-recovery before-the-change.age | tar -tv
```

It's audited as `product.backup.export`. Reading one back into a box is for
[#2](https://github.com/Sneakers-PAM/sneakers-appliance/issues/2) and
[#6](https://github.com/Sneakers-PAM/sneakers-appliance/issues/6).

### Removing one

`backup remove` is an owner's, with the name typed again and a new authenticator code, and is audited
as `product.backup.remove`. The box never removes a set itself.

## Restoring

```sh
sneakers backup restore before-the-change
```

An owner's, over SSH, with the set's name typed again and a new authenticator code. The product is
offline for it, and what was written after the point is gone once the box settles. Updates and the
console follow it as a step, ahead of the phases.

What refuses it, with nothing changed:

- `BACKUP_OTHER_BOX`: the set was made on a box holding other keys. The data couldn't be opened here,
  so the box won't half-do it. Restoring onto a different box is for
  [#2](https://github.com/Sneakers-PAM/sneakers-appliance/issues/2) and
  [#6](https://github.com/Sneakers-PAM/sneakers-appliance/issues/6).
- `BACKUP_ROOM`: the data volume can't hold the restored data beside the data it keeps, plus 1 GiB of
  WAL. The refusal says how much it needs.
- `BACKUP_BUSY`: an update or another restore is running, or the box hasn't settled on a data move. An
  update is refused the same way while a restore runs.

The steps:

1. **Verify.** Every file of the set is read back against the manifest.
2. **Stop.** The phases after the cluster's stop, then the cluster.
3. **Aside.** The data directory and the archive are renamed to `.pre-restore`, on their own volumes.
4. **Restore.** The cluster's identity is cleared and it starts with the declared environment. The
   chart's restore bootstrap fetches the base backup, replays to the point and promotes.
5. **Check.** Each of the product's checks runs on the restored data; for Sneakers, the audit chain.
6. **Finish.** The cluster stops, the environment comes off, and the phase loop brings the product
   up as on any boot.
7. **Settle.** Once the product is ready, what was moved aside goes, and the cluster takes a base
   backup in its new archive.

The restored cluster starts a new timeline and a new archive, because the old archive's WAL runs on
past the point. Every set holds its own WAL, so all of them still restore.

### When it fails

Every failure ends the same way. The cluster stops, the environment comes off, whatever the attempt
wrote is removed, `.pre-restore` is renamed back, and the product comes up on the data the box had.
Status says why, and `product.backup.restore.failed` goes in the audit log.

The journal is `/var/lib/sneakers/platform/backup-restore.json`, written and synced before each step.
A restore found running at the next start was cut off: it counts as failed, and it goes back. A way
back that's cut off carries on where it stopped. A product that doesn't come up on the restored data
within 30 minutes goes back too. Until the box settles, nothing has been thrown away.

## A full backup partition

A full backup partition warns and never stops the database. That takes the box's help.

PostgreSQL keeps every WAL file until `archive_command` takes it, and WAL-G can't write to a full
partition, so WAL piles up in `pg_wal` on the data volume. Neither `max_wal_size` nor
`max_slot_wal_keep_size` applies to WAL waiting for the archive. Left alone it fills the volume the
database runs on, and PostgreSQL stops. helm-postgres-ha doesn't bound this: it warns with
`PostgresHAArchiveFailing`, and it keeps `archive_command` to itself
(`postgresql.parameters.archive_command` is refused), so the box can't change what the command does.
Its retention can't help either, because it only runs after a base backup succeeds, and on a full
partition none does.

So the box bounds it from outside (`internal/backupset`, `Guard`, every minute in accessd), with no
retention setting involved. Once the oldest waiting file hasn't changed for 5 minutes, WAL is still
arriving, and over 1 GiB is waiting, it marks the oldest files archived, by renaming their
`archive_status` entries from `.ready` to `.done`. PostgreSQL then recycles them at its next
checkpoint. No file is removed by the box. At the data volume's critical level (90%) it doesn't wait
the 5 minutes. An archive that's slow but moving is left alone, however long the queue, and so is a
database that isn't writing.

That costs the archive a gap. The box records it in `platform/backup-archive.json`, audits
`product.backup.wal-dropped`, and Status says which files. A restore can't cross a gap, so
`backup create` takes a new base backup after one, and that base backup closes it. With the partition
still full, that base backup fails with `BACKUP_ROOM`, and the database runs on.

On a full partition WAL-G leaves an unfinished `.tmp.` file at every try. The guard clears any over an
hour old, and they never count as archived.

## What Status says

A backup problem is degraded, never down: it's a warning on Status and the console
(`WARNING_KIND_BACKUP`), and it doesn't touch the database's or the gateway's readiness.

- WAL archiving has stood still for 15 minutes.
- The box let WAL files go, until the next base backup.
- There's no base backup, the newest is over 48 hours old, or the last one failed.
- The last restore check failed.
- The last restore failed and the box went back.

The partition's own use warns at 80% and 90%, like every volume ([disk-layout.md](disk-layout.md)).

## Removing the product

`sneakers reset` removes `<dir>` with the data, the journal and the record of gaps. The chart refuses
to start a new cluster on an archive that already holds another cluster's WAL, so a new install
needs it gone.

## Testing it

The unit tests need nothing:

```sh
go test ./internal/backupset/
```

The rehearsal runs the real `internal/backupset` inside a kind node against the real chart, with the
box's values and a small ext4 file as the partition. It takes a sneakers-release checkout and nothing
else:

```sh
kind create cluster --name backups
CHARTS=../sneakers-release bash test/backups/rehearsal.sh
```

It writes rows, cuts a set, writes more, then SIGKILLs the restore at four steps and shows the box
back on every row each time. It refuses a set from another box and catches a damaged one. It then
restores: the first rows are there, the later ones aren't, and the audit chain passes. It restores
again from a set cut after the first restore, runs the chart's restore check, fills the partition
under load with the guard running and shows the database carry on, then frees room and restores a
set cut after the gap. The services aren't in it.

The real-bundle job's `backup` leg ([testing.md](testing.md#the-real-bundle-job)) does a restore on a
box in QEMU, with the services, through the closed shell, and a power loss after it.
