# Image slots and boot counting

A release reaches the box as one signed and encrypted update package, the `.bin`, downloaded from
the GitHub Release or uploaded by hand ([release.md](release.md)). The box verifies the signature
and the channel before it decrypts anything, with the update key read from the UKI it booted; a lab package never installs on a production box.

A box holds at most two releases: the one it runs and one more (the next, or the previous).

- `Image.Stage` fetches a release, runs the whole verification chain against the keys compiled
  into the running init, and refuses anything not newer than the running release
  (`UPGRADE_DOWNGRADE`). Nothing is written before that passes. It then writes the root image into
  the slot the box isn't running from (setting that slot's PARTUUID from the root hash), adds a
  sealed copy of the state key for the new UKI (PCR 7 as it is now and the predicted PCR 11), and
  only then writes the ESP entry `EFI/Linux/sneakers-<version>+3-0.efi`. Entries other than the
  running release's are removed first.
- systemd-boot boots the newest entry; each attempt moves one try from left to done
  (`+2-1`, `+1-2`, ...). An entry with no tries left is bad and sorts last, so after three failed
  boots the box falls back to the previous release, and `Image.Status` reports the failed version.
- `Image.MarkGood`, after the health checks, renames the running entry to `sneakers-<version>.efi`
  and prunes sealed copies for UKIs no longer kept.
- `Image.Rollback` marks the running release bad (`+0-n`), so the next boot is the previous one.
  With no previous release it's `UPGRADE_NO_PREVIOUS`.
- With Secure Boot off (TPM mode), the new release's PCR 4 must be predicted from the firmware's
  event log; until that replay is in, staging is refused (`UPGRADE_UNPREDICTABLE`) rather than
  sealed to a guess.

## Updating from :8443

The Updates page drives the same flow for an uploaded or a fetched `.bin`:

1. **Get the file.** Upload it (`POST /upload`, any admin) or fetch it from the configured mirror
   (`UpgradeService.FetchUpdate`, the file name such as `sneakers-appliance-0.2.0-amd64.bin`). With
   no mirror the box is air-gapped: it never makes a network fetch (`UPGRADE_AIR_GAPPED`) and upload
   is the only path. The mirror is an `https://` URL; the environment's proxy applies.
2. **Stage** (owner, step-up). The signature, the channel and the payload's SHA-256 are verified
   before anything is decrypted or unpacked; a patch must name the running version as a base.
   A refused file (`UPGRADE_SIGNATURE`, `UPGRADE_CHANNEL`, `UPGRADE_FORMAT`,
   `UPGRADE_PATCH_BASE`) is deleted, never unpacked, and the refusal is audited. Only then is the
   update key read from the booted UKI (by accessd, as root; [access.md](access.md#the-update-key)), the payload decrypted and unpacked, and the layout handed to
   `Image.Stage`.
3. **Apply** (owner, step-up) activates the staged release and reboots into it (`UPGRADE_NOT_STAGED`
   when nothing is staged). **Revert** rolls back to the previous release and reboots.

**The policy** (owner, step-up): `automatic` applies a staged release once inside the daily window
(default 02:00 local for 2 hours, 45 to 720 minutes), `manual` only when an owner applies it. It's
kept in `/var/lib/sneakers/osadmin-api/upgrade-policy.json`. **The history** of every fetch, stage, apply
and revert, with its outcome and code, is in `/var/lib/sneakers/osadmin-api/upgrade-history.jsonl` and
on the page, newest first.
