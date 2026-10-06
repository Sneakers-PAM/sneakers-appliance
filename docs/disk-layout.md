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

- The smallest disk is 64 GiB (`--disk-size`, 64G by default). A disk grown before the first
  power-on (an OVA disk, or a larger bare disk) gets the extra space in state and backup; nothing
  is stranded.
- Partitions are 1 MiB aligned. Backup starts on an aligned boundary and runs to the end of the
  usable space, so it may be a little over its share.
- `loader.conf`: no menu timeout, no editor, no auto-detected entries, the newest `sneakers-*`
  entry by default, and systemd-boot's own Secure Boot enrolment off (init enrols on an installed
  disk).
- The first install's UKI has no boot counter: it's known good. Upgrades add counted entries.
