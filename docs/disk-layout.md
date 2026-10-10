# Disk layout

The installed disk (spec 1, Section 3.2). `sneakers-kit build --format raw` writes partitions 1 to
3 into a sparse file, in Go, without root or loop devices; first boot creates the rest to fill
whatever disk the box really has.

| # | GPT label | Type | Size | Written by |
|---|---|---|---|---|
| 1 | `ESP` | EFI System | 1 GiB | the kit: FAT32 with `EFI/BOOT/BOOTX64.EFI` (systemd-boot), `EFI/Linux/sneakers-<version>.efi` (the UKI), `loader/loader.conf` and `loader/keys/sneakers/{PK,KEK,db}.auth` |
| 2 | `sneakers-root-a` | Linux root (x86-64) | 8 GiB | the kit: the root image; PARTUUID = the first 128 bits of its verity root hash |
| 3 | `sneakers-root-b` | Linux root (x86-64) | 8 GiB | empty until the first upgrade |
| 4 | `sneakers-keyfile` | Linux data | 16 MiB | first boot, key-file mode only |
| 5 | `sneakers-state` | Linux LUKS | the rest | first boot |
| 6 | `sneakers-backup` | Linux LUKS | 30% of the free space, at least 16 GiB | first boot, at the end of the disk |

- First boot's partitions are made at its protection step and then unlocked on every boot: state
  is mounted at `/var/lib`, backup at `/var/lib/sneakers/backup` ([key-custody.md](key-custody.md#at-boot)).
- The smallest disk is 64 GiB (`--disk-size`, 64G by default). A disk grown before the first
  power-on (an OVA disk, or a larger bare disk) gets the extra space in state and backup; nothing
  is stranded.
- Partitions are 1 MiB aligned. Backup starts on an aligned boundary and runs to the end of the
  usable space, so it may be a little over its share.
- `loader.conf`: no menu timeout, no editor, no auto-detected entries, the newest `sneakers-*`
  entry by default, and systemd-boot's own Secure Boot enrolment off (init enrols on an installed
  disk).
- The first install's UKI has no boot counter: it's known good. Upgrades add counted entries.

## Keeping the disk from filling

A box with a full state volume stops in ways that are hard to undo: the database refuses writes,
the kubelet evicts pods, the OS audit log can't append and no update can stage. The disk guard
(`internal/diskguard`, run by accessd) keeps the box from getting there by itself, and warns early
when it can't.

### What grows, and its cap

The box runs sneakers-init, not systemd, so there is no journald: init's and the services' output
goes to `/run/sneakers/console.log` on tmpfs (1 MiB, then `console.log.1`), never to disk. What does
reach the disk is capped:

| What | Where | Cap |
|---|---|---|
| Pod logs | `/var/log` (a link to `/var/lib/log`) | the kubelet rotates each container's log at 10 MiB and keeps 3 (`containerLogMaxSize`, `containerLogMaxFiles`); the cleanup holds all of them to 2% of the state volume (between 256 MiB and 2 GiB), and removes every rotated file while the volume has less than 15% free (between 1 GiB and 16 GiB): the journal-style size cap and keep-free floor |
| The OS audit log | `/var/lib/sneakers/os-audit/` | a file rolls over at 16 MiB within its day; closed files are compressed; the archive is held to 5% of the state volume (at least 512 MiB) and 2000 files, its oldest files moving to the backup volume ([os-audit.md](os-audit.md#rotation-and-the-archive)) |
| Containerd's images | `/var/lib/k0s` | the cleanup removes the images neither product slot needs; the kubelet's own image garbage collection is the last resort, from 90% down to 85% |
| Update files | `/var/lib/sneakers/osadmin-api/uploads/`, `/var/lib/sneakers/image-stage/` | an upload or fetch nobody staged goes after 7 days; partial uploads and cut-off stage work after an hour |
| Temporary files | `/tmp` (tmpfs) | files not changed for 7 days |
| The database's write-ahead log | the product's data path (`product.yaml` `data`) | PostgreSQL's own `max_wal_size` (512 MB in the Sneakers bundle); the box warns past the declared `wal_warn` (1 GiB) and never removes a WAL file |

The kubelet's settings are explicit in the box's own worker profile (`sneakers`, in
`os/k0s/k0s.yaml.tmpl`; k0s-interim starts k0s with `--profile sneakers`), not left to its defaults.
Eviction starts at 5% free (`nodefs.available`, `imagefs.available` and both `inodesFree`), with
`memory.available` at the kubelet's 100Mi: the default `imagefs.available` of 15% would evict the
product's pods at 85% full, because images and pods share the one state volume.

### The cleanup

The cleanup runs every hour, and at once whenever a volume passes 80%. An admin can run it from
**Clean up now** on :8443 Status (with a fresh authenticator code) or with `disk cleanup` in the
closed shell. Its steps, in order:

1. `pod-logs`: rotated pod logs, oldest first, to the cap and the floor above. A container's live
   log (`<n>.log`) is never touched.
2. `os-audit`: compress the closed audit files and keep the archive within its cap.
3. `images`: containerd images that neither product slot's bundle carries (the running release and
   the revert target, by the digests their archives are named for), that the k0s and containerd
   config don't pin, that no container uses and that containerd doesn't pin itself. With no slot
   image found, or containerd not answering, nothing is removed.
4. `updates`: held uploads past their retention, partial uploads and cut-off stage work; nothing
   while a file is coming in or a stage runs.
5. `tmp`: stale temporary files.
6. `wal`: checks each declared write-ahead log against its limit; it frees nothing.

Every run writes one `disk.cleanup.run` entry to the OS audit log: `detail.trigger` (`timer`, `alert`
or `admin`), `detail.freed`, and `detail.freed.<step>` for each step, with `detail.note.<step>`
and `detail.error.<step>` when there is something to say. A failed step doesn't stop the others.

### The safety list

The cleanup removes files only inside its own roots (`/var/lib/log`, the uploads and stage
directories and `/tmp`), and never anything on the safety list, inside it or holding it, whatever a
step asks for: the product data (`/var/lib/sneakers-data`), the backups and the escrow
(`/var/lib/sneakers/backup`), the secrets and keys (`access`, `ssh`, `sealed`, `osadmin`,
`osadmin-api/tls`, `platform`), both product slots (`product`, the running release and its revert
target) and both Base Web slots (`web`), setup, settings, the network's state, the import
directory, the box's name and machine id, k0s's data (`/var/lib/k0s`; images go only through
containerd) and the ESP (`/run/sneakers/esp`). A link is never followed. The OS audit log isn't
under the cleanup's roots either: only its own code compresses and moves it, keeping the chain.
`internal/diskguard`'s tests build a tree with every protected path, run every step against it (and
a step that tries to remove each protected path), and check the tree is byte for byte as it was.

### Alerts and warnings

Each volume is checked every minute: the state volume, the product data (on the state volume, so no
alert of its own unless a box gives it a volume) and the backup volume. 80% used is a **warning**,
90% **critical**; a level clears 5 points below where it starts (75% and 85%), so a use that
wobbles around a threshold doesn't flap. The levels are kept across restarts. Each change is
audited: `disk.alert.start` with `detail.level` when a level is reached, `disk.alert.clear` with
the level that cleared and `detail.now` when it drops, both with `detail.volume`, `detail.percent`,
`detail.used` and `detail.total`.

The guard also samples every hour, keeping a day of samples: each volume's use and each data path
the installed bundle's `product.yaml` declares (`data`, [release.md](release.md#productyaml); with
none declared, every directory under `/var/lib/sneakers-data`). Status warns when:

- a volume is at its warning or critical level (`WARNING_KIND_DISK_SPACE`, `critical` set at 90%);
- a volume would fill within a week at the last day's rate (`WARNING_KIND_DISK_GROWTH`). The rate
  needs at least 6 hours of hourly samples, so a one-off fill isn't read as a day's growth (the
  space warning covers it), and the warning says what the volume really grew over that span;
- a data path's write-ahead log is over its `wal_warn` (`WARNING_KIND_DATA_WAL`);
- the OS audit archive has files flagged to move to the backup volume, or files past their
  retention stay because the backup volume's archive can't take them (`WARNING_KIND_AUDIT_ARCHIVE`,
  [os-audit.md](os-audit.md#retention)).

The warnings show on :8443 Status and on the console's status screen (a critical one in the alert
colour). Status also carries each volume with its level (`volumes`), the data paths with their size,
growth and WAL (`data_paths`) and the last cleanup with what each step freed (`last_cleanup`).
