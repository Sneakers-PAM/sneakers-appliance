# Power and the factory reset

Init carries out every reboot, shutdown and factory reset. osadmin (the :8443 Power page) and the
closed shell decide whether the person may ask; init checks which program is asking, writes the OS
audit entries, and does the work.

## Who init answers

`PowerService` is served on `/run/sneakers/init.sock` (root only) and, alone, on
`/run/sneakers/power.sock` (mode 0666, for the closed shell's admin logins). On both, every
connection's peer is read with `SO_PEERCRED`, and init reads the peer's program from
`/proc/<pid>/exe`:

| Program | Reboot, power-off | Arm, cancel, run a factory reset |
|---|---|---|
| `/usr/bin/sneakers-osadmin` | yes | yes |
| `/usr/bin/sneakers-shell` as root (the console) or as an admin uid | yes | no |
| anything else | `POWER_CALLER` | `POWER_CALLER` |

Every request is audited with the caller (`detail.caller`, `uid`, `pid`), whether it was refused or
carried out. A request init can't audit (the OS audit log isn't writable) is refused with
`POWER_AUDIT`; a second power action while one is under way is refused with `POWER_BUSY`.

## Reboot and shutdown

Graceful, the default:

1. Audit the request (`power.reboot` or `power.shutdown`, `outcome: accepted`) and answer it.
2. Drain the services in reverse `after:` order, so k0s stops before platformd. Each gets its
   `stop-timeout` after SIGTERM before SIGKILL; the whole drain is bounded at 5 minutes. A drain
   that fails is logged and audited (`outcome: drain-failed`) and the box still goes down.
3. Audit the outcome, sync, unmount everything under `/var/lib` deepest first and close the LUKS
   mappings, unmount the ESP, sync again.
4. Reboot or power off.

Forced skips the drain and the unmounts: it audits the request and the outcome, syncs, and acts.
osadmin only sends a forced request after its second confirmation.

## The factory reset

### Authorization at init

osadmin runs the quorum, the 10-minute countdown and Cancel ([access.md](access.md)). Init doesn't
take its word for it:

- **Arm.** When the quorum's last approval lands, osadmin calls `ArmFactoryReset` with the request
  id, who started it and who approved. Init reads the access store itself and refuses
  (`RESET_QUORUM`) unless the starter is an owner and the approvals are distinct members of the
  roster in force, at least its threshold. Only then does osadmin start its countdown.
- **Delay.** Init counts its own 10 minutes from the arming, on its monotonic clock, so a clock
  step doesn't shorten it.
- **Cancel.** osadmin's Cancel (any admin, or the console) calls `CancelFactoryReset`; init forgets
  the reset. A reboot forgets it too: the armed reset lives only in init's memory.
- **Run.** `FactoryReset` runs only if it names the armed request with the same starter and
  approvals, the delay is over, it's within 5 minutes after the delay (later it has expired and is
  forgotten), and the approvals are still a quorum of the roster as it is now. Anything else is
  `RESET_QUORUM`, audited as refused.

### What it destroys

The key-file, state and backup partitions and every key that opens them. It keeps the ESP, both
root slots (the installed release) and the Secure Boot variables. The steps, each logged to the
console:

1. **Record.** Before anything is touched, `reset.json` on the ESP records the request and each
   partition it will destroy (number, label, start, size).
2. **Stop.** Drain every service but the console, unmount the state and backup volumes and close
   their LUKS mappings.
3. **Overwrite.** For each partition, the first 16 MiB (both LUKS2 headers, their JSON areas, and so
   the TPM-sealed copies of the state key, which are LUKS2 tokens, and every key slot) and the last
   1 MiB with random data, then the first 4 MiB with zeros, as `wipefs` would. The 16 MiB key-file
   partition is overwritten whole.
4. **Delete** the partitions from both GPT copies, and drop them from the kernel's view
   (`BLKPG_DEL_PARTITION`, which works while the ESP on the same disk stays mounted). A partition is
   deleted only when its number, label and start match the record.
5. **Check.** Re-read the primary GPT and the backup GPT at the end of the disk: none of the three
   partitions may be listed, the first 4 MiB of where each was must be zeros, and no LUKS header
   magic may be left in its first 16 MiB. A failure is `RESET_VERIFY`: the reset stops, shows the
   check that failed, and the box doesn't reboot.
6. **Done.** `reset.json` is marked `done` with the time: the one record that survives, beside the
   OS audit log that went with the state volume. Then reboot.

The next boot finds no state partition, so it's a genuine first boot with Secure Boot still
enrolled. First boot plans its partitions into the free space after the installed ones, which the
reset gives back whole.

The TPM itself holds no state-key object: the sealed copies are LUKS2 tokens and go with the
header. Init doesn't clear the TPM (`TPM2_Clear` needs the platform or lockout authorisation and
would also wipe what the firmware keeps there).

### Power cuts

Each step is written to `reset.json` before the next starts. The record is written to
`reset.json.new`, synced and renamed over the old one; if a cut on FAT leaves only the new name,
it's read instead. On every boot init reads the record first:

- No record, or a record marked `done`: the boot carries on as usual.
- A record not `done`, or one that doesn't read: the boot is in the `reset` phase. Init starts
  nothing and finishes the reset from the first step not recorded (the steps are safe to repeat),
  then reboots into first boot. If it can't finish, it shows why on the console and stays there.

So a box never comes back half-reset with its old data readable: once the record exists, the only
ways forward are finishing the reset or stopping with the reason on the console. A reset that
fails while the box is running (a volume that won't unmount, for instance) reboots so the boot
finishes it with nothing mounted; only a failed check stops without rebooting.

### Why it can't brick the box

A sister project's reset erased the key slots and kept the partition and its LUKS header; its init
decided first boot by whether the device was LUKS, so the node could neither open nor re-format the
volume and rebooted forever. Here the partitions are removed and checked gone, and first boot is
decided by their absence. The tests run a reset on a disk image laid out as a box after first boot,
then lay first boot's partitions out again in both GPT copies and reset a second time; they reset
the TPM and the key-file layouts, and cut the power at every write of a reset and resume it.
